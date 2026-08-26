import asyncio
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

            async def probe(scheme: str) -> Discovery:
                url = f"{scheme}://{target}"

                try:
                    response = await client.get(url)

                    return Discovery(
                        kind="http_probe",
                        data={
                            "requested_url": url,
                            "final_url": str(response.url),
                            "status": response.status_code,
                            "server": response.headers.get("server", ""),
                        },
                    )

                except asyncio.TimeoutError:
                    return Discovery(
                        kind="http_error",
                        data={"url": url, "error": "request timed out", "timeout": self.metadata.timeout},
                    )
                except (httpx.HTTPError, ScopedHTTPError) as e:
                    return Discovery(
                        kind="http_error",
                        data={
                            "url": url,
                            "error": str(e),
                        },
                    )

            discoveries = await asyncio.gather(
                *(asyncio.wait_for(probe(scheme), timeout=self.metadata.timeout) for scheme in ("https", "http"))
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
