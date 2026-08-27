from __future__ import annotations

from typing import Sequence

from sh4q.plugins import Discovery

from .interface import AdapterContext, ExternalToolAdapter


class SubfinderAdapter(ExternalToolAdapter):
    """Passive Subfinder adapter with a deliberately fixed argument set."""

    name = "subfinder"
    version_arguments: Sequence[str] = ("-version",)

    def __init__(self, executable: str = "subfinder"):
        self.executable = executable

    def build_argv(self, target: str, context: AdapterContext) -> Sequence[str]:
        # -silent keeps stdout machine-readable; no user-supplied flags are
        # accepted, so callers cannot enable active crawling or arbitrary files.
        return (self.executable, "-silent", "-d", target)

    def parse_stdout(self, target: str, stdout: str) -> list[Discovery]:
        names: set[str] = set()
        for line in stdout.splitlines():
            name = line.strip().lower().rstrip(".")
            if name and name != target.lower().rstrip("."):
                names.add(name)
        return [
            Discovery(
                kind="subdomain_found",
                data={"domain": target, "hostname": name, "source": self.name},
            )
            for name in sorted(names)
        ]

    def evidence_argv(self, argv: Sequence[str]) -> list[str]:
        return [argv[0], "-silent", "-d", "<target>"]
