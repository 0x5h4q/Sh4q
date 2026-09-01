from __future__ import annotations

import re
from typing import Sequence

from sh4q.plugins import Discovery

from .interface import AdapterContext, ExternalToolAdapter


class AmassPassiveAdapter(ExternalToolAdapter):
    """Passive Amass enumeration with a fixed, machine-readable command."""

    name = "amass-passive"
    version_arguments: Sequence[str] = ("-version",)

    def __init__(self, executable: str = "amass"):
        self.executable = executable

    def build_argv(self, target: str, context: AdapterContext) -> Sequence[str]:
        return (
            self.executable,
            "enum",
            "-passive",
            "-nocolor",
            "-d",
            target,
        )

    def parse_stdout(self, target: str, stdout: str) -> list[Discovery]:
        normalized_target = target.lower().rstrip(".")
        names: set[str] = set()
        suffix = re.escape(normalized_target)
        fqdn_pattern = re.compile(
            rf"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.{suffix})(?![A-Za-z0-9_-])",
            re.IGNORECASE,
        )
        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            matches = fqdn_pattern.findall(stripped)
            if matches:
                names.update(match.lower().rstrip(".") for match in matches)
            elif "-->" not in stripped:
                names.add(stripped.lower().rstrip("."))
        names.discard(normalized_target)
        return [
            Discovery(
                kind="subdomain_found",
                data={
                    "domain": target,
                    "hostname": name,
                    "source": self.name,
                },
            )
            for name in sorted(names)
        ]

    def evidence_argv(self, argv: Sequence[str]) -> list[str]:
        return [argv[0], "enum", "-passive", "-nocolor", "-d", "<target>"]
