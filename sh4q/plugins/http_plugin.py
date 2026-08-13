

import asyncio

import httpx

from .discovery import Discovery
from .interface import Plugin, PluginMetadata


class HTTPPlugin(Plugin):
    metadata = PluginMetadata(
        name="http",
        dependencies=["dns"],
        risk_level="active-low",   
        timeout=10.0,
    )

    async def execute(self, target: str) -> list[Discovery]:
        async with httpx.AsyncClient(follow_redirects=True, timeout=self.metadata.timeout) as client:

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
                except httpx.HTTPError as e:
                    return Discovery(kind="http_error", data={"url": url, "error": str(e)})

            return list(await asyncio.gather(probe("https"), probe("http")))