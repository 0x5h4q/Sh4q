"""
sh4q/plugins/http_plugin.py

Depends on "dns" — the Scheduler's dependency ordering (already proven)
guarantees this runs after the DNS plugin, though it doesn't actually
consume DNS's output directly; it just makes sense conceptually to
resolve before probing.

Reports the FINAL url after redirects, not just the requested one. This
matters: a redirect can land on a genuinely different host than the one
that was authorized — the exact same "newly discovered target needs its
own scope check" situation as the CDN-IP case in the DNS handler, just
reached via redirect instead of DNS resolution.
"""

import asyncio

import httpx

from .discovery import Discovery
from .interface import Plugin, PluginMetadata


class HTTPPlugin(Plugin):
    metadata = PluginMetadata(
        name="http",
        dependencies=["dns"],
        risk_level="active-low",   # genuine network interaction with the target, but not exploitative
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