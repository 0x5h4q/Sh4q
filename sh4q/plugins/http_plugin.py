import asyncio
import time
from collections.abc import Callable

import httpx
from sh4q.scope import ScopeEngine

from .discovery import Discovery
from .interface import Plugin, PluginMetadata
from sh4q.network import ScopedHTTPClient, ScopedHTTPError


class HTTPPlugin(Plugin):
    metadata = PluginMetadata(
        name="http",
        dependencies=["dns"],
        risk_level="active-low",
        timeout=10.0,
    )

    def __init__(self, scope: ScopeEngine, client_factory: Callable | None = None):
        self.scope = scope
        self._client_factory = client_factory or (
            lambda: ScopedHTTPClient(self.scope, timeout=self.metadata.timeout)
        )

    async def execute(self, target: str) -> list[Discovery]:
        async with self._client_factory() as client:
            # Finish slightly before the scheduler's plugin deadline so
            # timeout diagnostics can be published as discoveries.
            probe_timeout = max(0.1, self.metadata.timeout * 0.9)

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

        return list(unique.values())
