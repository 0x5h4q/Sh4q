from __future__ import annotations

import asyncio

from sh4q.network import RequestLimiter
from sh4q.scope import ScopeEngine

from .discovery import Discovery
from .http_plugin import HTTPPlugin
from .interface import Plugin, PluginMetadata


class DiscoveredHTTPPlugin(Plugin):
    """Probe hostnames that resolved successfully in the discovered-DNS stage."""

    metadata = PluginMetadata(
        name="discovered-http",
        dependencies=["discovered-dns"],
        timeout=300.0,
        risk_level="active-low",
    )

    def __init__(
        self,
        scope: ScopeEngine,
        limiter: RequestLimiter | None = None,
        max_names: int = 200,
        max_concurrent: int = 10,
        client_factory=None,
    ):
        self._scope = scope
        self._limiter = limiter
        self._max_names = max(1, max_names)
        self._semaphore = asyncio.Semaphore(max(1, max_concurrent))
        self._client_factory = client_factory
        self._names: list[str] = []

    def accept_discoveries(
        self, discoveries: list[Discovery], source_plugin: str | None = None
    ) -> None:
        if source_plugin != "discovered-dns":
            return
        names = {
            item.data.get("domain", "").lower().rstrip(".")
            for item in discoveries
            if item.kind == "discovered_dns_resolution" and item.data.get("domain")
        }
        self._names = sorted(
            name for name in names if self._scope.authorize(name).allowed
        )[: self._max_names]

    async def execute(self, target: str) -> list[Discovery]:
        tasks = [asyncio.create_task(self._probe(name)) for name in self._names]
        try:
            batches = await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        return [item for batch in batches for item in batch]

    async def _probe(self, name: str) -> list[Discovery]:
        async with self._semaphore:
            plugin = HTTPPlugin(
                self._scope,
                client_factory=self._client_factory,
                limiter=self._limiter,
            )
            return await plugin.execute(name)
