import asyncio
import time
from collections.abc import Callable

import httpx
from sh4q.scope import ScopeEngine

from .discovery import Discovery
from .interface import Plugin, PluginMetadata
from sh4q.network import RequestLimiter, ScopedHTTPClient, ScopedHTTPError


def _header_fingerprints(probe: Discovery) -> list[Discovery]:
    observations = []
    for header, value in (
        ("server", probe.data.get("server", "")),
        ("x-powered-by", probe.data.get("powered_by", "")),
    ):
        raw = str(value).strip()
        if not raw:
            continue
        product = raw.split("/", 1)[0].split(" ", 1)[0].strip()
        if not product:
            continue
        observations.append(
            Discovery(
                kind="http_fingerprint",
                data={
                    "endpoint": probe.data["final_url"],
                    "status": probe.data["status"],
                    "title": "",
                    "technologies": [product],
                    "detection_method": f"http-header:{header}",
                    "confidence": "explicit-header",
                    "source": "native-http",
                    "raw_observation": raw,
                },
            )
        )
    return observations


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
    ):
        self.scope = scope
        self._client_factory = client_factory or (
            lambda: ScopedHTTPClient(
                self.scope, timeout=self.metadata.timeout, limiter=limiter
            )
        )

    async def execute(self, target: str) -> list[Discovery]:
        async with self._client_factory() as client:
            # Finish slightly before the scheduler's plugin deadline so
            # timeout diagnostics can be published as discoveries.
            # Leave time for both probes and transport cleanup before the
            # scheduler's hard plugin timeout expires.
            probe_timeout = max(0.1, self.metadata.timeout * 0.7)

            async def probe(scheme: str) -> Discovery:
                url = f"{scheme}://{target}"
                started = time.monotonic()

                try:
                    response = await client.get(url)

                    return Discovery(
                        kind="http_probe",
                        data={
                            "requested_url": url,
                            "final_url": str(response.url),
                            "status": response.status_code,
                            "server": response.headers.get("server", ""),
                            "powered_by": response.headers.get("x-powered-by", ""),
                            "duration_seconds": round(time.monotonic() - started, 3),
                            "address": getattr(response, "extensions", {}).get("sh4q_pinned_ip"),
                        },
                    )

                except asyncio.TimeoutError:
                    return Discovery(
                        kind="http_error",
                        data={"url": url, "error": "request timed out", "phase": "overall", "timeout": self.metadata.timeout, "duration_seconds": round(time.monotonic() - started, 3)},
                    )
                except (httpx.HTTPError, ScopedHTTPError) as e:
                    return Discovery(
                        kind="http_error",
                        data={
                            "url": url,
                            "error": str(e),
                            "phase": getattr(e, "phase", "http"),
                            "duration_seconds": round(time.monotonic() - started, 3),
                            "address": getattr(e, "address", None),
                        },
                    )

            async def bounded_probe(scheme: str) -> Discovery:
                try:
                    return await asyncio.wait_for(probe(scheme), timeout=probe_timeout)
                except asyncio.TimeoutError:
                    url = f"{scheme}://{target}"
                    return Discovery(
                        kind="http_error",
                        data={
                            "url": url,
                            "error": "request timed out",
                            "phase": "overall",
                            "timeout": probe_timeout,
                        },
                    )

            discoveries = await asyncio.gather(
                *(bounded_probe(scheme) for scheme in ("https", "http"))
            )

        unique: dict[tuple, Discovery] = {}

        for discovery in discoveries:
            if discovery.kind != "http_probe":
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

        results = list(unique.values())
        fingerprints = [
            fingerprint
            for discovery in results
            if discovery.kind == "http_probe"
            for fingerprint in _header_fingerprints(discovery)
        ]
        return [*results, *fingerprints]
