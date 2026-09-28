import asyncio
import ssl
import time
from collections.abc import Callable

import httpx
from sh4q.scope import ScopeEngine

from .discovery import Discovery
from .interface import Plugin, PluginMetadata
from sh4q.network import RequestLimiter, ScopedHTTPClient, ScopedHTTPError, probe_targets, probe_url
from sh4q.fingerprints import extract_http_metadata, fingerprint_response


class HTTPPlugin(Plugin):
    metadata = PluginMetadata(
        name="http",
        dependencies=["dns"],
        risk_level="active-low",
        timeout=10.0,
    )

    def __init__(
        self,
        scope: ScopeEngine,
        client_factory: Callable | None = None,
        limiter: RequestLimiter | None = None,
        resolver: Callable | None = None,
        enforce_overall_probe_timeout: bool = True,
        include_html_sample: bool = False,
        timeout: float | None = None,
    ):
        self.scope = scope
        probe_timeout = timeout if timeout is not None else self.metadata.timeout
        if probe_timeout <= 0:
            raise ValueError("timeout must be positive")
        # Probes run concurrently but are rate limited, so the stage deadline
        # scales with how many origins the scope authorizes. A default 80/443
        # scope yields two probes and the original deadline.
        origins = max(1, len(probe_targets(scope.authorized_ports)))
        self.metadata = PluginMetadata(
            name="http",
            dependencies=["dns"],
            risk_level="active-low",
            timeout=probe_timeout * max(1, (origins + 1) // 2) + 1.0,
        )
        self._probe_timeout = probe_timeout
        self._enforce_overall_probe_timeout = enforce_overall_probe_timeout
        self._include_html_sample = include_html_sample
        self._client_factory = client_factory or (
            lambda: ScopedHTTPClient(
                self.scope,
                timeout=self._probe_timeout,
                limiter=limiter,
                resolver=resolver,
            )
        )

    async def execute(self, target: str) -> list[Discovery]:
        async with self._client_factory() as client:
            probe_timeout = min(self._probe_timeout, self.metadata.timeout)

            async def probe(origin: tuple[str, int]) -> Discovery:
                scheme, port = origin
                url = probe_url(scheme, target, port)
                started = time.monotonic()

                try:
                    response = await client.get(url)
                    metadata = extract_http_metadata(response)
                    probe_data = {
                        "requested_url": url,
                        "final_url": str(response.url),
                        "status": response.status_code,
                        "server": response.headers.get("server", ""),
                        "powered_by": response.headers.get("x-powered-by", ""),
                        "title": metadata["title"],
                        "content_type": metadata["content_type"],
                        "cookie_names": metadata["cookie_names"],
                        "sample_bytes": metadata["sample_bytes"],
                        "sample_truncated": metadata["sample_truncated"],
                        "duration_seconds": round(time.monotonic() - started, 3),
                        "address": getattr(response, "extensions", {}).get("sh4q_pinned_ip"),
                    }
                    if self._include_html_sample:
                        probe_data["html_sample"] = metadata.get("html_sample", "")
                    probe = Discovery(
                        kind="http_probe",
                        data=probe_data,
                    )
                    return [probe, *fingerprint_response(str(response.url), response.status_code, response, metadata)]

                except asyncio.TimeoutError:
                    return [Discovery(
                        kind="http_error",
                        data={"url": url, "error": "request timed out", "phase": "overall", "timeout": probe_timeout, "duration_seconds": round(time.monotonic() - started, 3), "retryable": True},
                    )]
                except (httpx.HTTPError, ScopedHTTPError, ssl.SSLError) as e:
                    detail = str(e).strip() or f"{e.__class__.__name__} without detail"
                    return [Discovery(
                        kind="http_error",
                        data={
                            "url": url,
                            "error": detail,
                            "phase": getattr(e, "phase", "http"),
                            "duration_seconds": round(time.monotonic() - started, 3),
                            "address": getattr(e, "address", None),
                        },
                    )]

            async def bounded_probe(origin: tuple[str, int]) -> Discovery:
                if not self._enforce_overall_probe_timeout:
                    return await probe(origin)
                try:
                    return await asyncio.wait_for(probe(origin), timeout=probe_timeout)
                except asyncio.TimeoutError:
                    url = probe_url(origin[0], target, origin[1])
                    return [Discovery(
                        kind="http_error",
                        data={
                            "url": url,
                            "error": "request timed out",
                            "phase": "overall",
                            "timeout": probe_timeout,
                            "retryable": True,
                        },
                    )]

            # Every authorized port is probed, not only the well-known pair.
            batches = await asyncio.gather(
                *(bounded_probe(origin) for origin in probe_targets(self.scope.authorized_ports))
            )
            discoveries = [item for batch in batches for item in batch]

        unique: dict[tuple, Discovery] = {}

        for discovery in discoveries:
            if discovery.kind == "http_fingerprint":
                key = (
                    discovery.kind,
                    discovery.data.get("endpoint"),
                    tuple(discovery.data.get("technologies") or []),
                )
            elif discovery.kind != "http_probe":
                key = (
                    discovery.kind,
                    discovery.data.get("url"),
                    discovery.data.get("error"),
                )
            else:
                key = (
                    discovery.kind,
                    discovery.data.get("final_url"),
                    discovery.data.get("status"),
                )

            unique[key] = discovery

        return list(unique.values())
