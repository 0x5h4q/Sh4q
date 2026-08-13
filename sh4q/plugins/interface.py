

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
    risk_level: str = "passive"   


class Plugin(ABC):
    metadata: PluginMetadata

    async def preflight(self) -> bool:
        return True

    @abstractmethod
    async def execute(self, target: str) -> list[Discovery]:
        
        ...

    async def cleanup(self) -> None:
        pass