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
        per_name_timeout: float = 3.0,
    ):
        self._names: list[str] = []
        self._max_names = max(1, max_names)
        self._semaphore = asyncio.Semaphore(max(1, max_concurrent))
        self._resolver = resolver or self._resolve
        self._scope = scope
        self._per_name_timeout = max(0.1, per_name_timeout)

    def accept_discoveries(
        self, discoveries: list[Discovery], source_plugin: str | None = None
    ) -> None:
        if source_plugin != "subfinder":
            return
        names = {
            item.data.get("hostname", "").lower().rstrip(".")
            for item in discoveries
            if item.kind == "subdomain_found" and item.data.get("hostname")
        }
        if self._scope is not None:
            names = {name for name in names if self._scope.authorize(name).allowed}
        self._names = sorted(names)[: self._max_names]

    async def execute(self, target: str) -> list[Discovery]:
        tasks = [asyncio.create_task(self._resolve_name(name)) for name in self._names]
        try:
            batches = await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for task in tasks:
                if not task.done():
                    task.cancel()
            batches = await asyncio.gather(*tasks, return_exceptions=True)
            partial = [
                item
                for batch in batches
                if isinstance(batch, list)
                for item in batch
            ]
            return partial
        return [item for batch in batches for item in batch]

    async def _resolve_name(self, name: str) -> list[Discovery]:
        async with self._semaphore:
            try:
                ips = await asyncio.wait_for(
                    self._resolver(name), timeout=self._per_name_timeout
                )
                if not ips:
                    return [Discovery("discovered_dns_error", {"domain": name, "error": "no addresses returned"})]
                return [
                    Discovery("discovered_dns_resolution", {"domain": name, "ip": ip})
                    for ip in sorted(set(ips))
                ]
            except TimeoutError:
                return [
                    Discovery(
                        "discovered_dns_error",
                        {"domain": name, "error": "resolution timed out", "timeout": self._per_name_timeout},
                    )
                ]
            except OSError as error:
                return [Discovery("discovered_dns_error", {"domain": name, "error": str(error)})]

    @staticmethod
    async def _resolve(name: str) -> list[str]:
        loop = asyncio.get_running_loop()
        results = await loop.getaddrinfo(name, None)
        return sorted({info[4][0] for info in results})
