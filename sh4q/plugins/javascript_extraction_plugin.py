from __future__ import annotations

from collections.abc import Awaitable, Callable

from sh4q.javascript_extraction import (
    JavaScriptExtractionLimits,
    extract_javascript_observations,
)

from .discovery import Discovery
from .interface import Plugin, PluginMetadata


class JavaScriptExtractionPlugin(Plugin):
    """Extract passive references from scan-owned HTTP response samples."""

    metadata = PluginMetadata(
        name="javascript-extraction",
        dependencies=["http"],
        risk_level="passive",
        timeout=15.0,
    )

    def __init__(
        self,
        observations_provider: Callable[[str], Awaitable[list[dict]]],
        limits: JavaScriptExtractionLimits | None = None,
    ):
        self._observations_provider = observations_provider
        self._limits = limits or JavaScriptExtractionLimits()

    async def execute(self, target: str) -> list[Discovery]:
        discoveries: list[Discovery] = []
        for observation in await self._observations_provider(target):
            endpoint = observation.get("endpoint")
            content = observation.get("content", "")
            if not endpoint or not isinstance(content, str):
                continue
            for extracted in extract_javascript_observations(
                content,
                endpoint,
                self._limits,
            ):
                discoveries.append(
                    Discovery(
                        kind=f"javascript_{extracted['kind']}",
                        data={
                            **extracted,
                            "source_endpoint": endpoint,
                        },
                    )
                )
        return discoveries
