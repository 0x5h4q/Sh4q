from __future__ import annotations

import asyncio
import socket
from collections.abc import Awaitable, Callable

from .discovery import Discovery
from .interface import Plugin, PluginMetadata
from sh4q.scope import ScopeEngine


class DiscoveredDNSPlugin(Plugin):
    """Resolve names emitted by an earlier discovery plugin."""

    metadata = PluginMetadata(
        name="discovered-dns",
        dependencies=["subfinder"],
        timeout=120.0,
        risk_level="passive",
    )

    def __init__(
        self,
        max_names: int = 1000,
        max_concurrent: int = 20,
        resolver: Callable[[str], Awaitable[list[str]]] | None = None,
        scope: ScopeEngine | None = None,
    ):
        self._names: list[str] = []
        self._max_names = max(1, max_names)
        self._semaphore = asyncio.Semaphore(max(1, max_concurrent))
        self._resolver = resolver or self._resolve
        self._scope = scope

    def accept_discoveries(self, discoveries: list[Discovery]) -> None:
        names = {
            item.data.get("hostname", "").lower().rstrip(".")
            for item in discoveries
            if item.kind == "subdomain_found" and item.data.get("hostname")
        }
        if self._scope is not None:
            names = {name for name in names if self._scope.authorize(name).allowed}
        self._names = sorted(names)[: self._max_names]

    async def execute(self, target: str) -> list[Discovery]:
        batches = await asyncio.gather(*(self._resolve_name(name) for name in self._names))
        return [item for batch in batches for item in batch]

    async def _resolve_name(self, name: str) -> list[Discovery]:
        async with self._semaphore:
            try:
                ips = await self._resolver(name)
                if not ips:
                    return [Discovery("discovered_dns_error", {"domain": name, "error": "no addresses returned"})]
                return [
                    Discovery("discovered_dns_resolution", {"domain": name, "ip": ip})
                    for ip in sorted(set(ips))
                ]
            except OSError as error:
                return [Discovery("discovered_dns_error", {"domain": name, "error": str(error)})]

    @staticmethod
    async def _resolve(name: str) -> list[str]:
        loop = asyncio.get_running_loop()
        results = await loop.getaddrinfo(name, None)
        return sorted({info[4][0] for info in results})
