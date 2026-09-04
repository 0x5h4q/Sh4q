from __future__ import annotations

from urllib.parse import urlsplit
from typing import Sequence

from sh4q.plugins import Discovery

from .interface import AdapterContext, ExternalToolAdapter


class URLHistoryAdapter(ExternalToolAdapter):
    """Parse passive URL-history output without treating URLs as live."""

    name = "url-history"
    version_arguments: Sequence[str] = ("--version",)

    def __init__(self, executable: str = "gau"):
        self.executable = executable

    def build_argv(self, target: str, context: AdapterContext) -> Sequence[str]:
        # gau accepts a target argument and --subs expands to subdomains. No
        # active crawling or arbitrary input/output paths are enabled here.
        return (self.executable, "--subs", target)

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
        return [
            Discovery(
                kind="url_history_found",
                data={"domain": target, "url": value, "source": self.name},
            )
            for value in sorted(urls)
        ]

    def evidence_argv(self, argv: Sequence[str]) -> list[str]:
        return [argv[0], "--subs", "<target>"]
