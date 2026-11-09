from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Sequence

from sh4q.plugins import Discovery, Plugin, PluginMetadata
from sh4q.scope import ScopeEngine


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
        from urllib.parse import urlsplit
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


class URLHistoryAdapter(Plugin):
    """Query the Wayback Machine CDX API directly for historical URLs.

    Replaces the waybackurls external-tool dependency: the CDX API is queried
    over HTTP and the results are parsed in-process. This avoids depending on
    an external binary that may be missing or broken.
    """

    metadata = PluginMetadata(name="url-history", timeout=60.0, risk_level="external-controlled")

    CDX_API = "http://web.archive.org/cdx/search/cdx"

    def __init__(self, scope: ScopeEngine, *, max_urls: int = 5000):
        if max_urls < 1:
            raise ValueError("max_urls must be positive")
        self._scope = scope
        self._max_urls = max_urls

    def _query_cdx(self, domain: str) -> list[str]:
        """Query the CDX API for archived URLs under *domain.

        Returns the raw original URLs from the `fl=original` field.
        """
        url = (
            f"{self.CDX_API}?url=*.{domain}"
            f"&output=text&fl=original&collapse=urlkey&limit={self._max_urls}"
        )
        try:
            with urllib.request.urlopen(url, timeout=30.0) as response:
                body = response.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError, ValueError):
            return []
        urls: list[str] = []
        for line in body.splitlines():
            value = line.strip()
            if not value:
                continue
            urls.append(value)
        return urls

    async def execute(self, target: str) -> list[Discovery]:
        """Query the CDX API for historical URLs under *target.

        Scope checking is done by the handler (discovered-http-style), so this
        adapter returns every URL the CDX API knows about; the handler refuses
        anything out of scope.
        """
        urls = self._query_cdx(target)
        values = _select(urls, self._max_urls)
        discoveries = [
            Discovery(
                kind="url_history_batch",
                data={"domain": target, "urls": values, "source": self.name},
            )
        ]
        if len(urls) > self._max_urls:
            discoveries.append(
                Discovery(
                    kind="url_history_truncated",
                    data={
                        "domain": target,
                        "retained": self._max_urls,
                        "available": len(urls),
                        "source": self.name,
                    },
                )
            )
        return discoveries
