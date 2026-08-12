
"""
sh4q/plugins/dns_plugin.py

The first real plugin. Uses asyncio's built-in DNS resolution (no new
library needed — this is part of the standard library's event loop API).

Notice this file knows NOTHING about Scheduler, EventBus, Scope, or
Storage. It only knows: given a target, resolve it, report what was found.
Everything else — Gate 1, publishing, Gate 2, normalization, persistence —
happens outside this file, exactly as designed.
"""

import asyncio

from .discovery import Discovery
from .interface import Plugin, PluginMetadata


class DNSPlugin(Plugin):
    metadata = PluginMetadata(
        name="dns",
        risk_level="passive",   # pure DNS lookups — no interaction with the target itself
        timeout=5.0,
    )

    async def execute(self, target: str) -> list[Discovery]:
        loop = asyncio.get_running_loop()
        try:
            # getaddrinfo is asyncio's built-in async DNS resolution —
            # same "await pauses, event loop moves on" mechanics you
            # already know from httpx calls.
            results = await loop.getaddrinfo(target, None)
        except OSError as e:
            # DNS failures (NXDOMAIN, timeout, etc.) are a normal outcome,
            # not a crash — report it as a discovery, don't raise.
            return [Discovery(kind="dns_error", data={"domain": target, "error": str(e)})]

        # getaddrinfo can return duplicate entries (IPv4/IPv6 variants,
        # multiple socket types for the same address) — dedupe to one
        # discovery per unique IP.
        ips = sorted({info[4][0] for info in results})
        return [
            Discovery(kind="dns_resolution", data={"domain": target, "ip": ip})
            for ip in ips
        ]