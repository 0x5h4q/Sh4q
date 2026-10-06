from __future__ import annotations

from urllib.parse import urlsplit
from typing import Sequence

from sh4q.plugins import Discovery

from .interface import AdapterContext, ExternalToolAdapter


def _select(values: list[str], limit: int) -> list[str]:
    """Choose which URLs to keep when there are more than the bound.

    `sorted(values)[:limit]` is a prefix of the alphabet, not a sample, and
    the consequences are systematic rather than proportional. On a real scan
    it kept 5000 of 14658: 91% of the kept set was one host, only 20 distinct
    hosts appeared, and every one of the 30 https URLs was discarded -- not
    because they mattered less, but because "http://" sorts before "https://"
    and the cut landed inside the http block.

    Round-robin across hosts so every host is represented, and spread evenly
    within each host so the selection covers that host's range instead of its
    first few paths. Deterministic throughout: the same input always produces
    the same selection, which is what makes a diff between two scans mean
    something.
    """
    if len(values) <= limit:
        return values

    by_host: dict[str, list[str]] = {}
    for value in values:
        host = urlsplit(value).hostname or ""
        by_host.setdefault(host, []).append(value)

    # An even share each, with the remainder going to the hosts that have the
    # most to offer rather than to whichever sorts first.
    hosts = sorted(by_host)
    share = {host: limit // len(hosts) for host in hosts}
    for host in sorted(hosts, key=lambda h: (-len(by_host[h]), h))[: limit % len(hosts)]:
        share[host] += 1

    chosen: list[str] = []
    leftover = 0
    for host in hosts:
        group = by_host[host]
        want = share[host]
        if len(group) <= want:
            chosen.extend(group)
            leftover += want - len(group)
            continue
        step = len(group) / want
        chosen.extend(group[int(index * step)] for index in range(want))

    # Hosts with less than their share free up budget; give it to the rest in
    # the same even-spread way rather than letting it fall to the alphabet.
    if leftover:
        remaining = [v for v in values if v not in set(chosen)]
        if remaining:
            take = min(leftover, len(remaining))
            step = len(remaining) / take
            chosen.extend(remaining[int(index * step)] for index in range(take))

    return sorted(dict.fromkeys(chosen))


class URLHistoryAdapter(ExternalToolAdapter):
    """Parse passive URL-history output without treating URLs as live."""

    name = "url-history"
    version_arguments: Sequence[str] = ("--version",)

    def __init__(self, executable: str = "waybackurls", *, max_urls: int = 5000):
        if max_urls < 1:
            raise ValueError("max_urls must be positive")
        self.executable = executable
        self.max_urls = max_urls

    def build_argv(self, target: str, context: AdapterContext) -> Sequence[str]:
        # Pass the target as an argument, matching the supported Waybackurls
        # invocation used by operators and avoiding stdin-dependent behavior.
        return (self.executable, target.rstrip(".\n"))

    def parse_stdout(self, target: str, stdout: str) -> list[Discovery]:
        root = target.lower().rstrip(".")
        urls: set[str] = set()
        for line in stdout.splitlines():
            value = line.strip()
            if not value or len(value) > 8192:
                continue
            try:
                parsed = urlsplit(value)
            except ValueError:
                continue
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                continue
            hostname = parsed.hostname.lower().rstrip(".")
            if hostname == root or hostname.endswith("." + root):
                # Hostnames are case-insensitive; retain path/query casing.
                try:
                    host = hostname + (f":{parsed.port}" if parsed.port else "")
                except ValueError:
                    continue
                normalized = parsed._replace(netloc=host).geturl()
                urls.add(normalized)
        values = sorted(urls)
        discoveries = [Discovery(
            kind="url_history_batch",
            data={"domain": target, "urls": _select(values, self.max_urls), "source": self.name},
        )]
        if len(values) > self.max_urls:
            discoveries.append(Discovery(
                kind="url_history_truncated",
                data={"domain": target, "retained": self.max_urls, "available": len(urls), "source": self.name},
            ))
        return discoveries

    def evidence_argv(self, argv: Sequence[str]) -> list[str]:
        return [argv[0], "<target>"]
