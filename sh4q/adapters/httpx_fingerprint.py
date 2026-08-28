from __future__ import annotations

import json
from typing import Sequence

from sh4q.plugins import Discovery

from .interface import AdapterContext, ExternalToolAdapter


class HttpxFingerprintAdapter(ExternalToolAdapter):
    """Candidate ProjectDiscovery httpx adapter with structured JSONL output."""

    name = "httpx-fingerprint"
    version_arguments: Sequence[str] = ("-version",)

    def __init__(self, executable: str = "httpx"):
        self.executable = executable

    def build_argv(self, target: str, context: AdapterContext) -> Sequence[str]:
        # Redirect following is deliberately not enabled. Live integration is
        # deferred until endpoint-fed execution and containment are validated.
        return (
            self.executable,
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-u",
            target,
        )

    def parse_stdout(self, target: str, stdout: str) -> list[Discovery]:
        discoveries: list[Discovery] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            endpoint = record.get("url") or record.get("input") or target
            technologies = record.get("tech") or []
            if isinstance(technologies, str):
                technologies = [technologies]
            discoveries.append(
                Discovery(
                    kind="http_fingerprint",
                    data={
                        "endpoint": endpoint,
                        "status": record.get("status_code"),
                        "title": record.get("title", ""),
                        "technologies": sorted(set(technologies)),
                        "detection_method": "httpx-tech-detect",
                        "confidence": "tool-reported",
                        "source": self.name,
                    },
                )
            )
        return discoveries

    def evidence_argv(self, argv: Sequence[str]) -> list[str]:
        return [*argv[:-1], "<endpoint>"]
