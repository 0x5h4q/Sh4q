from __future__ import annotations

import json
import re
from typing import Sequence
from urllib.parse import urlsplit

from sh4q.plugins import Discovery

from .interface import AdapterContext, ExternalToolAdapter


class KatanaAdapter(ExternalToolAdapter):
    """Bounded Katana URL discovery for runtime-loaded web assets."""

    name = "katana"
    version_arguments: Sequence[str] = ("-version",)

    def __init__(
        self,
        executable: str = "katana",
        *,
        depth: int = 1,
        crawl_duration: str = "30s",
        max_response_size: int = 256 * 1024,
        timeout: int = 10,
        retries: int = 1,
    ):
        if depth < 1 or max_response_size < 1 or timeout < 1 or retries < 0:
            raise ValueError("Katana bounds must be positive (retries may be zero)")
        self.executable = executable
        self.depth = depth
        self.crawl_duration = crawl_duration
        self.max_response_size = max_response_size
        self.timeout = timeout
        self.retries = retries

    def build_argv(self, target: str, context: AdapterContext) -> Sequence[str]:
        return (
            self.executable,
            "-silent",
            "-u",
            f"https://{target}/",
            "-jc",
            "-xhr",
            "-j",
            "-d",
            str(self.depth),
            "-ct",
            self.crawl_duration,
            "-max-response-size",
            str(self.max_response_size),
            "-timeout",
            str(self.timeout),
            "-retry",
            str(self.retries),
            "-dr",
        )

    def parse_stdout(self, target: str, stdout: str) -> list[Discovery]:
        root = target.lower().rstrip(".")
        seed = f"https://{root}/"
        values: dict[str, str] = {}
        for line in stdout.splitlines():
            value = line.strip()
            if not value or len(value) > 8192:
                continue
            candidates: list[str] = []
            try:
                document = json.loads(value)
            except json.JSONDecodeError:
                candidates.append((value, None))
            else:
                candidates.extend(self._json_urls(document))
            for candidate, hint in candidates:
                self._record_url(candidate, root, seed, values, hint)
        return [
            Discovery(
                kind=f"javascript_{kind}",
                data={"value": value, "source_endpoint": seed, "source": self.name},
            )
            for value, kind in sorted(values.items())
        ]

    @staticmethod
    def _json_urls(value: object) -> list[tuple[str, str | None]]:
        found: list[tuple[str, str | None]] = []
        if isinstance(value, dict):
            for key, item in value.items():
                if key.lower() in {"url", "endpoint", "request_url", "xhr_url", "script_url"} and isinstance(item, str):
                    found.append((item, key.lower()))
                else:
                    found.extend(KatanaAdapter._json_urls(item))
        elif isinstance(value, list):
            for item in value:
                found.extend(KatanaAdapter._json_urls(item))
        return found

    @staticmethod
    def _record_url(value: str, root: str, seed: str, output: dict[str, str], hint: str | None = None) -> None:
        value = value.strip()
        if not value or value.rstrip("/").lower() == seed.rstrip("/").lower():
            return
        try:
            parsed = urlsplit(value)
        except ValueError:
            return
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return
        host = parsed.hostname.lower().rstrip(".")
        if host != root and not host.endswith("." + root):
            return
        normalized = parsed._replace(fragment="").geturl()
        path = parsed.path.lower()
        if hint == "xhr_url":
            kind = "xhr_endpoint"
        elif re.search(r"\.(?:js|mjs|cjs)(?:$|[?#])", path):
            kind = "script_url"
        elif re.search(r"\.css(?:$|[?#])", path):
            kind = "style_url"
        elif parsed.path in {"", "/"} or not parsed.path.rsplit("/", 1)[-1].count("."):
            kind = "page_url"
        else:
            kind = "endpoint_reference"
        output[normalized] = kind

    def evidence_argv(self, argv: Sequence[str]) -> list[str]:
        return [argv[0], "<bounded katana arguments>"]
