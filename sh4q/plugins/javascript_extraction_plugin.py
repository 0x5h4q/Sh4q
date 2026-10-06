from __future__ import annotations

from collections.abc import Awaitable, Callable

from sh4q.javascript_extraction import (
    JavaScriptExtractionLimits,
    extract_javascript_observations,
)

from sh4q.cli.branding import status_line

from .discovery import Discovery
from .interface import Plugin, PluginMetadata


class JavaScriptExtractionPlugin(Plugin):
    """Extract passive references from scan-owned HTTP response samples."""

    metadata = PluginMetadata(name="javascript-extraction", dependencies=["http"], risk_level="passive", timeout=15.0)

    def __init__(
        self,
        observations_provider: Callable[[str], Awaitable[list[dict]]],
        limits: JavaScriptExtractionLimits | None = None,
        after_discovered_http: bool = False,
    ):
        self.metadata = PluginMetadata(
            name="javascript-extraction",
            dependencies=["http", "discovered-http"] if after_discovered_http else ["http"],
            risk_level="passive",
            timeout=15.0,
        )
        self._observations_provider = observations_provider
        self._limits = limits or JavaScriptExtractionLimits()

    async def execute(self, target: str) -> list[Discovery]:
        discoveries: list[Discovery] = []
        examined = 0
        for observation in await self._observations_provider(target):
            endpoint = observation.get("endpoint")
            content = observation.get("content", "")
            if not endpoint or not isinstance(content, str):
                continue
            examined += 1
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
        # Zero references from three pages and zero pages examined are
        # different facts, and the stage used to report both as silence. On a
        # real scan it examined 21KB across three endpoints that contained no
        # <script> tag at all -- a correct result, indistinguishable from
        # having had no HTML to look at.
        if examined:
            print(status_line(
                f"examined {examined} endpoint(s) for JavaScript references; "
                f"found {len(discoveries)}"
            ))
        else:
            print(status_line(
                "no HTML was captured to examine for JavaScript references"
            ))
        return discoveries
