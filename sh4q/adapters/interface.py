from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from sh4q.plugins.discovery import Discovery
from sh4q.scope import ScopeEngine


@dataclass(frozen=True)
class AdapterContext:
    """Shared controls an external-tool adapter is allowed to use."""

    scope: ScopeEngine
    output_directory: Path


class ExternalToolAdapter:
    """Contract for external reconnaissance tools."""

    name: str
    version: str = "0.1.0"
    executable: str
    version_arguments: Sequence[str] = ("--version",)

    def build_argv(self, target: str, context: AdapterContext) -> Sequence[str]:
        """Return process arguments, never a shell command string."""
        raise NotImplementedError

    def parse_stdout(self, target: str, stdout: str) -> list[Discovery]:
        raise NotImplementedError

    def evidence_argv(self, argv: Sequence[str]) -> list[str]:
        """Return a secret-safe command representation for durable evidence."""
        return [argv[0], "<arguments redacted>"]

    def build_stdin(self, target: str, context: AdapterContext) -> bytes | None:
        """Return bounded stdin input for tools that read targets from stdin."""
        return None
