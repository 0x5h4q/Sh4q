
"""
sh4q/plugins/interface.py

The Plugin Interface — one of the six frozen contracts. Every recon
capability implements this same shape, regardless of what it actually does
internally (DNS lookup, HTTP probe, screenshot capture — all identical
from the Scheduler's point of view).

risk_level is captured here as decided: reserved metadata only, no
enforcement behavior yet. Revisit once real plugins exist to inform what
enforcement should actually look like.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .discovery import Discovery


@dataclass
class PluginMetadata:
    name: str
    version: str = "0.1.0"
    dependencies: list[str] = field(default_factory=list)   # names of plugins that must run first
    timeout: float = 30.0
    required_scope: list[str] = field(default_factory=list)  # reserved for future use
    risk_level: str = "passive"   # "passive" | "active-low" | "active" — metadata only, unenforced


class Plugin(ABC):
    metadata: PluginMetadata

    async def preflight(self) -> bool:
        """Is this plugin able to run at all right now — e.g. a required
        tool is installed, an API key is present? Default: always ready.

        This is NOT a scope check. Scope authorization for the target
        happens centrally, in the Scheduler, before execute() is ever
        called — a plugin has no say in whether it's allowed to run
        against a given target at all.
        """
        return True

    @abstractmethod
    async def execute(self, target: str) -> list[Discovery]:
        """Do the actual work against `target`. Returns what was
        observed as a list of Discovery objects. Never touches Storage
        or the Event bus directly — that's the engine's job, not the
        plugin's."""
        ...

    async def cleanup(self) -> None:
        """Release any resources (open connections, temp files, etc.).
        Default: nothing to clean up."""
        pass