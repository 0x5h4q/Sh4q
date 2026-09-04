from __future__ import annotations

from urllib.parse import urlsplit
from typing import Sequence

from sh4q.plugins import Discovery

from .interface import AdapterContext, ExternalToolAdapter


class URLHistoryAdapter(ExternalToolAdapter):
    """Parse passive URL-history output without treating URLs as live."""

    name = "url-history"
    version_arguments: Sequence[str] = ("--version",)

    def __init__(self, executable: str = "waybackurls", *, max_urls: int = 2000):
        if max_urls < 1:
            raise ValueError("max_urls must be positive")
        self.executable = executable
        self.max_urls = max_urls

    def build_argv(self, target: str, context: AdapterContext) -> Sequence[str]:
        # Waybackurls accepts one target and performs passive archive lookup.
        return (self.executable,)

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
            data={"domain": target, "urls": values[: self.max_urls], "source": self.name},
        )]
        if len(values) > self.max_urls:
            discoveries.append(Discovery(
                kind="url_history_truncated",
                data={"domain": target, "retained": self.max_urls, "available": len(urls), "source": self.name},
            ))
        return discoveries

    def evidence_argv(self, argv: Sequence[str]) -> list[str]:
        return [argv[0], "<stdin>"]

    def build_stdin(self, target: str, context: AdapterContext) -> bytes:
        return (target.rstrip(".\n") + "\n").encode("utf-8")
