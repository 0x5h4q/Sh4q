from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from sh4q.network import RequestLimiter
from sh4q.scope import ScopeEngine


@dataclass(frozen=True)
class AdapterContext:
    """Shared controls an external-tool adapter is allowed to use."""

    scope: ScopeEngine
    limiter: RequestLimiter
    output_directory: Path


class ExternalToolAdapter:
    """Contract for external reconnaissance tools."""

    name: str
    version: str = "0.1.0"

    def build_argv(self, target: str, context: AdapterContext) -> Sequence[str]:
        """Return process arguments, never a shell command string."""
        raise NotImplementedError
