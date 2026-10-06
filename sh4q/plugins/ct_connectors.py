import json
from dataclasses import dataclass

from urllib.parse import quote

import httpx

from sh4q.network import RequestLimiter, TrustedServiceHTTPClient


class CTConnectorError(Exception):
    def __init__(
        self,
        message: str,
        retryable: bool = True,
        rate_limited: bool = False,
        retry_after: int | None = None,
        partial_hostnames: set[str] | None = None,
    ):
        super().__init__(message)
        self.retryable = retryable
        self.rate_limited = rate_limited
        self.retry_after = retry_after
        self.partial_hostnames = partial_hostnames or set()


@dataclass(frozen=True)
class CTResult:
    hostnames: set[str]
    error: CTConnectorError | None = None


class CTConnector:
    name: str

    async def fetch_hostnames(
        self,
        target: str,
        timeout: float,
    ) -> list[str]:
        raise NotImplementedError


def _clean_hostname(name: str, target: str) -> str | None:
    name = name.strip().lower().rstrip(".")

    if name.startswith("*."):
        name = name[2:]

    if name and name != target and name.endswith(f".{target}"):
        return name

    return None


def _retry_after(response: httpx.Response) -> int | None:
    value = response.headers.get("Retry-After")

    if not value:
        return None

    try:
        return max(0, int(value))
    except ValueError:
        return None


class CertSpotterConnector(CTConnector):
    name = "certspotter"

    def __init__(self, max_pages: int = 50, client_factory=None, limiter: RequestLimiter | None = None):
        self.max_pages = max_pages
        self._client_factory = client_factory or (
            lambda timeout: TrustedServiceHTTPClient(
                {"api.certspotter.com"}, timeout=timeout, limiter=limiter
            )
        )

    async def fetch_hostnames(
        self,
        target: str,
        timeout: float,
    ) -> list[str]:
        hostnames: set[str] = set()
        after: str | None = None

        async with self._client_factory(timeout) as client:
            for _ in range(self.max_pages):
                params = {
                    "domain": target,
                    "include_subdomains": "true",
                    "expand": "dns_names",
                }

                if after:
                    params["after"] = after

                try:
                    response = await client.get(
                        "https://api.certspotter.com/v1/issuances",
                        params=params,
                    )
                except httpx.TimeoutException as e:
                    raise CTConnectorError(
                        f"certspotter timed out: {e}",
                        retryable=True,
                        partial_hostnames=hostnames,
                    ) from e
                except httpx.HTTPError as e:
                    raise CTConnectorError(
                        f"certspotter request failed: {e}",
                        retryable=True,
                        partial_hostnames=hostnames,
                    ) from e

                if response.status_code == 429:
                    retry_after = _retry_after(response)

                    message = "certspotter rate limited"

                    if retry_after is not None:
                        message += f" (Retry-After: {retry_after}s)"

                    raise CTConnectorError(
                        message,
                        retryable=False,
                        rate_limited=True,
                        retry_after=retry_after,
                        partial_hostnames=hostnames,
                    )

                if response.status_code != 200:
                    retryable = response.status_code in {
                        408,
                        500,
                        502,
                        503,
                        504,
                    }

                    raise CTConnectorError(
                        f"certspotter returned HTTP {response.status_code}",
                        retryable=retryable,
                        partial_hostnames=hostnames,
                    )

                try:
                    records = response.json()
                except json.JSONDecodeError as e:
                    raise CTConnectorError(
                        f"certspotter returned invalid JSON: {e}",
                        retryable=True,
                        partial_hostnames=hostnames,
                    ) from e

                if not isinstance(records, list):
                    raise CTConnectorError(
                        "certspotter returned an unexpected JSON structure",
                        retryable=True,
                        partial_hostnames=hostnames,
                    )

                if not records:
                    break

                for record in records:
                    dns_names = record.get("dns_names", [])

                    if not isinstance(dns_names, list):
                        continue

                    for name in dns_names:
                        if not isinstance(name, str):
                            continue

                        cleaned = _clean_hostname(name, target)

                        if cleaned:
                            hostnames.add(cleaned)

                next_after = records[-1].get("id")

                if not next_after or next_after == after:
                    break

                after = next_after

        return sorted(hostnames)


class CrtShConnector(CTConnector):
    name = "crt.sh"

    def __init__(self, max_records: int = 10000, client_factory=None, limiter: RequestLimiter | None = None):
        self.max_records = max_records
        self._client_factory = client_factory or (
            lambda timeout: TrustedServiceHTTPClient(
                {"crt.sh"}, timeout=timeout, limiter=limiter
            )
        )

    async def fetch_hostnames(
        self,
        target: str,
        timeout: float,
    ) -> list[str]:
        try:
            async with self._client_factory(timeout) as client:
                response = await client.get(
                    "https://crt.sh/",
                    params={
                        "q": f"%.{target}",
                        "output": "json",
                    },
                )
        except httpx.TimeoutException as e:
            raise CTConnectorError(
                f"crt.sh timed out: {e}",
                retryable=True,
            ) from e
        except httpx.HTTPError as e:
            raise CTConnectorError(
                f"crt.sh request failed: {e}",
                retryable=True,
            ) from e

        if response.status_code == 429:
            retry_after = _retry_after(response)

            message = "crt.sh rate limited"

            if retry_after is not None:
                message += f" (Retry-After: {retry_after}s)"

            raise CTConnectorError(
                message,
                retryable=False,
                rate_limited=True,
                retry_after=retry_after,
            )

        if response.status_code != 200:
            retryable = response.status_code in {
                408,
                500,
                502,
                503,
                504,
            }

            raise CTConnectorError(
                f"crt.sh returned HTTP {response.status_code}",
                retryable=retryable,
            )

        try:
            records = response.json()
        except json.JSONDecodeError as e:
            raise CTConnectorError(
                f"crt.sh returned invalid JSON: {e}",
                retryable=True,
            ) from e

        if not isinstance(records, list):
            raise CTConnectorError(
                "crt.sh returned an unexpected JSON structure",
                retryable=True,
            )

        hostnames: set[str] = set()

        for record in records[: self.max_records]:
            name_value = record.get("name_value", "")

            if not isinstance(name_value, str):
                continue

            for name in name_value.splitlines():
                cleaned = _clean_hostname(name, target)

                if cleaned:
                    hostnames.add(cleaned)

        return sorted(hostnames)


class CrtNameConnector(CTConnector):
    """crt.name, an opt-in third certificate-transparency source.

    Returns newline-delimited hostnames rather than JSON, so there is no
    envelope to validate and a body cut at the ceiling is still usable --
    unlike its JSON siblings, where a truncated response parses as nothing.

    `max_bytes` bounds what is parsed and retained, not what is transferred.
    `TrustedServiceHTTPClient` exposes only `get`, so all three CT connectors
    materialise the full response; a transfer-level cap would belong on that
    client and apply to all of them equally.

    Opt-in by default: every CT source is another party that learns which
    domain an operator is interested in. `certificate_transparency.sources`
    names them in the config so that disclosure is visible before a scan runs
    rather than inferred from the code afterwards.
    """

    name = "crt.name"

    def __init__(
        self,
        max_bytes: int = 8 * 1024 * 1024,
        client_factory=None,
        limiter: RequestLimiter | None = None,
    ):
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self.max_bytes = max_bytes
        self._client_factory = client_factory or (
            lambda timeout: TrustedServiceHTTPClient(
                {"crt.name"}, timeout=timeout, limiter=limiter
            )
        )

    async def fetch_hostnames(self, target: str, timeout: float) -> list[str]:
        url = f"https://crt.name/v1/search?apex={quote(target, safe='')}"
        try:
            async with self._client_factory(timeout) as client:
                response = await client.get(url)
        except httpx.TimeoutException as error:
            raise CTConnectorError(
                f"crt.name timed out: {error}", retryable=True
            ) from error
        except httpx.HTTPError as error:
            raise CTConnectorError(
                f"crt.name request failed: {error}", retryable=True
            ) from error

        if response.status_code == 429:
            retry_after = _retry_after(response)
            message = "crt.name rate limited"
            if retry_after is not None:
                message += f" (Retry-After: {retry_after}s)"
            raise CTConnectorError(
                message, retryable=False, rate_limited=True, retry_after=retry_after
            )

        if response.status_code != 200:
            # The service explains refusals in the body, and the explanation
            # is actionable: it answers only for a registrable apex, so a
            # subdomain gets "invalid apex: not an apex (eTLD+1 is nmap.org)".
            # Reporting a bare HTTP 400 leaves the operator with nothing to do
            # about it. sh4q does not guess the apex itself -- that needs a
            # public-suffix list, and guessing wrong on a name like
            # "example.edu.ng" would query a whole suffix.
            reason = " ".join(response.text.split())[:200]
            detail = f": {reason}" if reason else ""
            raise CTConnectorError(
                f"crt.name returned HTTP {response.status_code}{detail}",
                retryable=response.status_code in {408, 500, 502, 503, 504},
            )

        hostnames = set()
        for line in response.text[: self.max_bytes].splitlines():
            cleaned = _clean_hostname(line, target)
            if cleaned:
                hostnames.add(cleaned)
        return sorted(hostnames)


# Every certificate-transparency source, by the name a config may ask for.
# A source is a third party that learns which domain is being looked at, so
# the set is declared in configuration rather than fixed in code.
CT_CONNECTORS = {
    "certspotter": CertSpotterConnector,
    "crt.sh": CrtShConnector,
    "crt.name": CrtNameConnector,
}


def build_ct_connectors(
    sources, limiter: RequestLimiter | None = None
) -> list[CTConnector]:
    """Instantiate the named sources, preserving the order given."""
    return [CT_CONNECTORS[name](limiter=limiter) for name in sources]
