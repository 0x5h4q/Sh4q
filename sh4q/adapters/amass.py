from __future__ import annotations

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
        names = {
            line.strip().lower().rstrip(".")
            for line in stdout.splitlines()
            if line.strip()
        }
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
