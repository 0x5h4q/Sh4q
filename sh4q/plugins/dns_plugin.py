
"""

The first real plugin I made. I used asyncio's built-in DNS resolution.

Notice this file knows NOTHING -_- about Scheduler, EventBus, Scope, or Storage. It only knows: given a target, resolve it, report what was found.
Everything else i.e Gate 1, publishing, Gate 2, normalization, persistence, happens outside this file. ALl according to design ;)

"""

import asyncio

from .discovery import Discovery
from .interface import Plugin, PluginMetadata


class DNSPlugin(Plugin):
    metadata = PluginMetadata(
        name="dns",
        risk_level="passive",   # pure DNS lookups, no interaction with the target itself
        timeout=5.0,
    )

    async def execute(self, target: str) -> list[Discovery]:
        loop = asyncio.get_running_loop()
        try:
            results = await loop.getaddrinfo(target, None)
        except OSError as e:
            return [Discovery(kind="dns_error", data={"domain": target, "error": str(e)})]

        ips = sorted({info[4][0] for info in results})
        return [
            Discovery(kind="dns_resolution", data={"domain": target, "ip": ip})
            for ip in ips
        ]