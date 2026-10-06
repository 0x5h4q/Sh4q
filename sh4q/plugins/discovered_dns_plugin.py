from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
from collections.abc import Awaitable, Callable, Iterable

from .discovery import Discovery
from .interface import Plugin, PluginMetadata
from sh4q.scope import ScopeEngine
from sh4q.cli.branding import status_line
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

    #: The deadline this stage published before it scaled. Kept as a floor so
    #: a default run is bounded exactly as it was.
    MINIMUM_TIMEOUT = 300.0

    metadata = PluginMetadata(
        name="discovered-dns",
        # Passive discovery sources are optional and may be enabled
        # independently; scan_runner appends this stage after them.
        dependencies=[],
        timeout=MINIMUM_TIMEOUT,
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

        # A flat deadline cannot bound work the operator sizes. At 10 lookups
        # in flight and a 3s per-name timeout, 1500 names need up to 450s --
        # so a real scan configured for 1500 was certain to be cut off at the
        # old flat 300s, and 189 names were never queried. The bound, not the
        # names admitted later, is what the deadline has to cover: it is known
        # now, and it is the most the stage can be asked to do.
        worst_case = (self._max_names / max(1, max_concurrent)) * self._per_name_timeout
        self.metadata = PluginMetadata(
            name=type(self).metadata.name,
            dependencies=list(type(self).metadata.dependencies),
            risk_level=type(self).metadata.risk_level,
            timeout=max(self.MINIMUM_TIMEOUT, worst_case * 1.5 + 30.0),
        )
        # Which sources offered each name. A name two sources agree on is more
        # likely to be real than one only a permutation tool produced.
        self._sources: dict[str, set[str]] = {}
        if names:
            # An operator-supplied list enters through the same admission path
            # as a discovered name: scope-filtered, deduplicated, and bounded.
            self._admit(names, source="operator")

    def _admit(self, hostnames, *, source: str) -> None:
        for raw in hostnames:
            if not raw or not raw.strip():
                continue
            name = raw.lower().rstrip(".")
            if self._scope is not None and not self._scope.authorize(name).allowed:
                continue
            self._sources.setdefault(name, set()).add(source)
        self._names = self._select(self._sources, self._max_names)

    @staticmethod
    def _select(sources: dict[str, set[str]], limit: int) -> list[str]:
        """Choose which names to resolve when there are more than the bound.

        Taking the alphabetically first N is deterministic but systematically
        biased: on a real target, 500 names drawn from 1513 spent 62% of the
        budget on hostnames beginning with "c" and never reached anything
        after "m". Adding a second discovery source made coverage worse,
        because its output crowded the front of the alphabet.

        Prefer names an operator supplied, then names more than one source
        found, then spread the remainder evenly across the sorted rest so the
        sample covers the whole range. Deterministic throughout: the same
        input always produces the same selection.
        """
        operator = sorted(n for n, s in sources.items() if "operator" in s)
        corroborated = sorted(
            n for n, s in sources.items() if "operator" not in s and len(s) > 1
        )
        single = sorted(
            n for n, s in sources.items() if "operator" not in s and len(s) == 1
        )

        chosen: list[str] = operator[:limit]
        for group in (corroborated, single):
            remaining = limit - len(chosen)
            if remaining <= 0:
                break
            if len(group) <= remaining:
                chosen.extend(group)
            else:
                step = len(group) / remaining
                chosen.extend(group[int(index * step)] for index in range(remaining))
        return sorted(dict.fromkeys(chosen))

    def accept_discoveries(
        self, discoveries: list[Discovery], source_plugin: str | None = None
    ) -> None:
        if source_plugin not in SUBDOMAIN_SOURCES:
            return
        self._admit(
            (
                item.data.get("hostname", "")
                for item in discoveries
                if item.kind == "subdomain_found" and item.data.get("hostname")
            ),
            source=source_plugin or "unknown",
        )

    async def execute(self, target: str) -> list[Discovery]:
        if self._names:
            print(status_line(f"resolving {len(self._names)} discovered name(s)"))
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
            # Preserving the finished lookups is only half of it. This stage
            # kept partial results before any other did, but never said it had
            # been cut off -- and a suppressed cancellation never reaches
            # asyncio.wait_for, so the scheduler recorded a clean completion
            # over a partial stage. On a real scan it announced 1500 names, ran
            # past its 300s deadline, and 189 of them left no resolution and no
            # error: indistinguishable from names that do not exist.
            #
            # Unlike `http`/`ct`/`javascript-bundles`, this reports truncation
            # even when nothing resolved. Those stages re-raise on an empty
            # result because an empty return would read as "completed, found
            # nothing"; here the record itself carries the truth, so there is
            # no empty success to mistake it for.
            attempted = sum(1 for batch in batches if isinstance(batch, list))
            total = len(self._names)
            partial.append(Discovery("discovered_dns_truncated", {
                "total": total,
                "attempted": attempted,
                "not_attempted": total - attempted,
                "reason": "stage deadline reached before every name was looked up",
            }))
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
