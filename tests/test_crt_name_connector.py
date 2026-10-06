"""crt.name as an opt-in certificate-transparency source.

crt.sh is the flakiest part of a real scan: on one engagement it timed out
on all three attempts while certspotter's 184 names were the only result
that run produced. A third source is resilience, not redundancy.

It is opt-in rather than default because every CT source is another party
that learns which domain an operator is interested in, and that choice
belongs to the operator. `certificate_transparency.sources` names them
explicitly in the config so the disclosure is visible before the scan, not
inferred afterwards.

The endpoint returns newline-delimited hostnames rather than JSON, so this
connector is the one that must not assume a parseable structure.
"""

import asyncio

import httpx

from sh4q.config import Sh4qConfig
from sh4q.plugins.ct_connectors import CrtNameConnector, CTConnectorError
from sh4q.plugins.ct_plugin import CTPlugin


class FakeClient:
    """Stands in for TrustedServiceHTTPClient.

    It must offer the same surface the real client does. The first version of
    this fake invented a `get_text_bounded` method, which the real client does
    not have: the suite passed and the live scan died with
    "'TrustedServiceHTTPClient' object has no attribute 'get_text_bounded'".
    A fake that is more capable than its subject hides a broken integration,
    so the interface check at the bottom of this file now pins the two
    together.
    """

    def __init__(self, body="", status=200, headers=None, raises=None):
        self.body, self.status = body, status
        self.headers = headers or {}
        self.raises = raises
        self.urls: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, url, **kwargs):
        self.urls.append(url)
        if self.raises is not None:
            raise self.raises
        return httpx.Response(
            self.status, headers=self.headers,
            content=self.body.encode(), request=httpx.Request("GET", url),
        )


def connector_with(client) -> CrtNameConnector:
    return CrtNameConnector(client_factory=lambda timeout: client)


async def main() -> None:
    # --- the happy path: newline delimited, filtered, deduplicated --------
    client = FakeClient(body="\n".join([
        "example.com",                 # the apex itself is not a subdomain
        "api.example.com",
        "API.EXAMPLE.COM.",            # case and trailing dot
        "*.wild.example.com",          # wildcard prefix stripped
        "api.example.com",             # duplicate
        "elsewhere.test",              # a different zone
        "",                            # blank line
        "   admin.example.com   ",     # surrounding whitespace
    ]) + "\n")
    names = await connector_with(client).fetch_hostnames("example.com", 10.0)
    assert names == ["admin.example.com", "api.example.com", "wild.example.com"], names
    assert client.urls and "apex=example.com" in client.urls[0], client.urls
    assert client.urls[0].startswith("https://"), "must not fall back to http"

    # --- an empty body is a valid answer, not an error --------------------
    assert await connector_with(FakeClient(body="")).fetch_hostnames("example.com", 10.0) == []

    # --- the error taxonomy matches the other connectors ------------------
    limited = FakeClient(status=429, headers={"Retry-After": "60"})
    try:
        await connector_with(limited).fetch_hostnames("example.com", 10.0)
        raise AssertionError("429 must raise")
    except CTConnectorError as error:
        assert error.rate_limited is True
        assert error.retryable is False, "a provider asking us to slow down must not be retried"
        assert error.retry_after == 60, error.retry_after

    for status, retryable in ((502, True), (503, True), (404, False), (400, False)):
        try:
            await connector_with(FakeClient(status=status)).fetch_hostnames("example.com", 10.0)
            raise AssertionError(f"HTTP {status} must raise")
        except CTConnectorError as error:
            assert error.retryable is retryable, f"{status}: {error.retryable}"
            assert error.rate_limited is False

    # The service explains refusals in the body, and the explanation is the
    # actionable part: it answers only for a registrable apex, so a subdomain
    # target is refused with the apex it would accept. A bare "HTTP 400" left
    # an operator nothing to act on.
    explained = FakeClient(status=400, body="invalid apex: not an apex (eTLD+1 is nmap.org)")
    try:
        await connector_with(explained).fetch_hostnames("scanme.nmap.org", 10.0)
        raise AssertionError("400 must raise")
    except CTConnectorError as error:
        assert "invalid apex" in str(error), error
        assert "nmap.org" in str(error), error
        assert error.retryable is False

    # A refusal body is bounded and flattened; it reaches a terminal line.
    noisy = FakeClient(status=400, body="x" * 5000 + "\n\nmore")
    try:
        await connector_with(noisy).fetch_hostnames("example.com", 10.0)
        raise AssertionError("400 must raise")
    except CTConnectorError as error:
        assert len(str(error)) < 300, len(str(error))
        assert "\n" not in str(error)

    timed_out = FakeClient(raises=httpx.ConnectTimeout("too slow"))
    try:
        await connector_with(timed_out).fetch_hostnames("example.com", 10.0)
        raise AssertionError("a timeout must raise")
    except CTConnectorError as error:
        assert error.retryable is True
        assert "crt.name" in str(error)

    # --- a truncated body keeps what it read ------------------------------
    # The response is plain text with no envelope, so a body cut at the byte
    # ceiling is still usable. Discarding it would lose every name that did
    # arrive, which is the failure this project keeps finding.
    big = FakeClient(body="\n".join(f"h{i}.example.com" for i in range(5000)))
    partial = CrtNameConnector(client_factory=lambda t: big, max_bytes=200)
    kept = await partial.fetch_hostnames("example.com", 10.0)
    assert kept, "a truncated plain-text body must still yield the names it contained"
    assert all(n.endswith(".example.com") for n in kept)
    assert len(kept) < 5000, "the ceiling must actually bound the read"

    # --- it is not in the default source list -----------------------------
    default_names = {c.name for c in CTPlugin()._connectors}
    assert default_names == {"certspotter", "crt.sh"}, default_names
    assert "crt.name" not in default_names, (
        "a new third party must not start learning targets without being asked"
    )

    # --- but the config can ask for it ------------------------------------
    opted_in = Sh4qConfig(scope={"targets": ["example.com"]}, certificate_transparency={
        "sources": ["certspotter", "crt.sh", "crt.name"],
    })
    assert {c.name for c in CTPlugin(config=opted_in)._connectors} == {
        "certspotter", "crt.sh", "crt.name",
    }

    # A config may also narrow the set, which is the disclosure control.
    only_one = Sh4qConfig(scope={"targets": ["example.com"]}, certificate_transparency={
        "sources": ["crt.name"],
    })
    assert [c.name for c in CTPlugin(config=only_one)._connectors] == ["crt.name"]

    # An unknown source is refused at config load, not silently ignored.
    try:
        Sh4qConfig(scope={"targets": ["example.com"]},
                   certificate_transparency={"sources": ["not-a-source"]})
        raise AssertionError("an unknown CT source must be rejected")
    except Exception as error:
        assert "not-a-source" in str(error), error

    # --- the two lists that cannot import each other must agree ----------
    # The config validates source names; the plugin layer holds the
    # connectors. config -> plugins would close an import cycle, so this
    # assertion is what keeps them in step.
    from sh4q.config.schema import CT_SOURCE_NAMES, DEFAULT_CT_SOURCES
    from sh4q.plugins.ct_connectors import CT_CONNECTORS

    assert set(CT_SOURCE_NAMES) == set(CT_CONNECTORS), (
        f"config names {sorted(CT_SOURCE_NAMES)} but connectors are "
        f"{sorted(CT_CONNECTORS)}"
    )
    assert set(DEFAULT_CT_SOURCES) <= set(CT_CONNECTORS)
    for name, factory in CT_CONNECTORS.items():
        assert factory().name == name, f"{name} registered under the wrong key"

    # --- the fake may not be more capable than the real client -----------
    from sh4q.network import TrustedServiceHTTPClient

    real = {m for m in dir(TrustedServiceHTTPClient) if not m.startswith("_")}
    used = {m for m in dir(FakeClient) if not m.startswith("_")}
    assert used <= real, (
        f"the fake offers methods the real client does not: {sorted(used - real)}; "
        "a connector written against them passes here and fails on a real scan"
    )

    print("crt.name connector test passed")


asyncio.run(main())
