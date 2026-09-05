from __future__ import annotations

import asyncio

from sh4q.network import AsyncDNSResolver, RequestLimiter
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
        retry_on_timeout=False,
    )

    def __init__(
        self,
        scope: ScopeEngine,
        limiter: RequestLimiter | None = None,
        max_names: int = 200,
        max_concurrent: int = 10,
        client_factory=None,
        include_html_sample: bool = False,
        http_timeout: float | None = None,
    ):
        self._scope = scope
        self._limiter = limiter
        self._max_names = max(1, max_names)
        self._semaphore = asyncio.Semaphore(max(1, max_concurrent))
        self._client_factory = client_factory
        self._include_html_sample = include_html_sample
        self._http_timeout = http_timeout
        self._names: list[str] = []
        self._addresses: dict[str, set[str]] = {}
        self._redirect_resolver = AsyncDNSResolver()

    def accept_discoveries(
        self, discoveries: list[Discovery], source_plugin: str | None = None
    ) -> None:
        if source_plugin != "discovered-dns":
            return
        addresses: dict[str, set[str]] = {}
        for item in discoveries:
            if item.kind != "discovered_dns_resolution":
                continue
            name = item.data.get("domain", "").lower().rstrip(".")
            address = item.data.get("ip", "")
            if name and address:
                addresses.setdefault(name, set()).add(address)
        names = set(addresses)
        self._names = sorted(
            name for name in names if self._scope.authorize(name).allowed
        )[: self._max_names]
        self._addresses = {name: addresses[name] for name in self._names}

    async def execute(self, target: str) -> list[Discovery]:
        tasks = [asyncio.create_task(self._probe(name)) for name in self._names]
        try:
            batches = await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for task in tasks:
                if not task.done():
                    task.cancel()
            batches = await asyncio.gather(*tasks, return_exceptions=True)
            return [
                item
                for batch in batches
                if isinstance(batch, list)
                for item in batch
            ]
        return [item for batch in batches for item in batch]

    async def _probe(self, name: str) -> list[Discovery]:
        async with self._semaphore:
            async def resolve(host: str, port: int) -> list[str]:
                normalized = host.lower().rstrip(".")
                if normalized == name:
                    return sorted(self._addresses[name])
                return await self._redirect_resolver.resolve_addresses(normalized)

            try:
                plugin = HTTPPlugin(
                    self._scope,
                    client_factory=self._client_factory,
                    limiter=self._limiter,
                    resolver=resolve,
                    enforce_overall_probe_timeout=False,
                    include_html_sample=self._include_html_sample,
                    timeout=self._http_timeout,
                )
                return await plugin.execute(name)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                detail = str(error).strip() or f"{error.__class__.__name__} without detail"
                return [Discovery(
                    kind="http_error",
                    data={
                        "url": name,
                        "error": detail,
                        "phase": "host-probe",
                    },
                )]
