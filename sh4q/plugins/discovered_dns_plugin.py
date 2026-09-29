from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
from collections.abc import Awaitable, Callable, Iterable

from .discovery import Discovery
from .interface import Plugin, PluginMetadata
from sh4q.scope import ScopeEngine
from sh4q.network import AsyncDNSResolver, DNSResolutionError


# Stages that produce subdomain names worth resolving. Certificate
# transparency is one of them and was previously excluded, so its names --
# often the largest set a scan finds -- were never resolved or probed.
SUBDOMAIN_SOURCES = frozenset({"ct", "subfinder"})


@dataclass(frozen=True)
class HostLoadResult:
    accepted: tuple[str, ...]
    rejected: tuple[tuple[int, str, str], ...]
    duplicates: int


def normalize_host(raw: str) -> str | None:
    """Reduce one operator-supplied line to a hostname, or reject it.

    Accepts a bare hostname or a URL, since operators paste both.
    """
    value = raw.strip()
    if not value or value.startswith("#"):
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    if "://" in value:
        value = urlsplit(value).hostname or ""
    value = value.split("/", 1)[0].split("@")[-1]
    if value.startswith("[") and "]" in value:          # bracketed IPv6
        value = value[1 : value.index("]")]
    elif value.count(":") == 1:                          # host:port
        value = value.split(":", 1)[0]
    value = value.strip().rstrip(".").lower()
    if not value or " " in value:
        return None
    return value


def load_host_names(path: str | Path, *, max_hosts: int = 500) -> HostLoadResult:
    """Load a bounded, operator-supplied list of hostnames to check.

    Scope is not applied here. The plugin authorises every name before it
    resolves anything, so a file may safely contain out-of-scope entries;
    they are refused at Gate 2 and recorded as such.
    """
    if max_hosts < 1:
        raise ValueError("max_hosts must be positive")
    host_path = Path(path).expanduser()
    if not host_path.is_file():
        raise ValueError(f"host list not found: {host_path}")
    try:
        lines = host_path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError(f"host list is not valid UTF-8: {host_path}") from error

    accepted: list[str] = []
    rejected: list[tuple[int, str, str]] = []
    seen: set[str] = set()
    duplicates = 0
    for number, raw in enumerate(lines, 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        host = normalize_host(raw)
        if host is None:
            rejected.append((number, raw.strip(), "not a hostname"))
            continue
        if host in seen:
            duplicates += 1
            continue
        seen.add(host)
        if len(accepted) >= max_hosts:
            raise ValueError(f"host list exceeds the maximum of {max_hosts} names")
        accepted.append(host)
    return HostLoadResult(tuple(accepted), tuple(rejected), duplicates)


class DiscoveredDNSPlugin(Plugin):
    """Resolve names emitted by an earlier discovery plugin."""

    metadata = PluginMetadata(
        name="discovered-dns",
        # Passive discovery sources are optional and may be enabled
        # independently; scan_runner appends this stage after them.
        dependencies=[],
        timeout=300.0,
        risk_level="passive",
    )

    def __init__(
        self,
        max_names: int = 500,
        max_concurrent: int = 10,
        resolver: Callable[[str], Awaitable[list[str]]] | None = None,
        scope: ScopeEngine | None = None,
        per_name_timeout: float = 3.0,
        names: Iterable[str] | None = None,
    ):
        self._names: list[str] = []
        self._max_names = max(1, max_names)
        self._semaphore = asyncio.Semaphore(max(1, max_concurrent))
        self._per_name_timeout = max(0.1, per_name_timeout)
        self._dns = AsyncDNSResolver(lifetime=self._per_name_timeout)
        self._resolver = resolver or self._dns.resolve_addresses
        self._scope = scope
        if names:
            # An operator-supplied list enters through the same admission path
            # as a discovered name: scope-filtered, deduplicated, and bounded.
            self._admit(names)

    def _admit(self, hostnames) -> None:
        names = set(self._names)
        names.update(
            name.lower().rstrip(".") for name in hostnames if name and name.strip()
        )
        if self._scope is not None:
            names = {name for name in names if self._scope.authorize(name).allowed}
        self._names = sorted(names)[: self._max_names]

    def accept_discoveries(
        self, discoveries: list[Discovery], source_plugin: str | None = None
    ) -> None:
        if source_plugin not in SUBDOMAIN_SOURCES:
            return
        self._admit(
            item.data.get("hostname", "")
            for item in discoveries
            if item.kind == "subdomain_found" and item.data.get("hostname")
        )

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
            except DNSResolutionError as error:
                return [Discovery("discovered_dns_error", {
                    "domain": name,
                    "error": str(error),
                    "reason": error.code,
                })]
            except OSError as error:
                return [Discovery("discovered_dns_error", {"domain": name, "error": str(error)})]
