from __future__ import annotations

from collections.abc import Awaitable, Callable

from sh4q.javascript_extraction import (
    JavaScriptExtractionLimits,
    extract_javascript_observations,
    extract_javascript_bundle_observations,
)

from .discovery import Discovery
from .interface import Plugin, PluginMetadata


class JavaScriptBundlePlugin(Plugin):
    """Fetch a bounded set of discovered script bundles for passive parsing."""

    metadata = PluginMetadata(
        name="javascript-bundles",
        dependencies=["javascript-extraction"],
        risk_level="active-low",
        timeout=45.0,
    )

    def __init__(
        self,
        observations_provider: Callable[[str], Awaitable[list[dict]]],
        bundle_fetcher: Callable[[str], Awaitable[str | None]],
        limits: JavaScriptExtractionLimits | None = None,
        max_bundles: int = 10,
    ):
        self._observations_provider = observations_provider
        self._bundle_fetcher = bundle_fetcher
        self._limits = limits or JavaScriptExtractionLimits()
        self._max_bundles = max(1, max_bundles)

    async def execute(self, target: str) -> list[Discovery]:
        script_urls: list[str] = []
        seen: set[str] = set()
        for observation in await self._observations_provider(target):
            endpoint = observation.get("endpoint")
            content = observation.get("content", "")
            if not endpoint or not isinstance(content, str):
                continue
            for item in extract_javascript_observations(content, endpoint, self._limits):
                if item["kind"] != "script_url":
                    continue
                url = str(item["value"])
                if url not in seen:
                    seen.add(url)
                    script_urls.append(url)
                if len(script_urls) >= self._max_bundles:
                    break
            if len(script_urls) >= self._max_bundles:
                break

        discoveries: list[Discovery] = []
        for script_url in script_urls:
            try:
                content = await self._bundle_fetcher(script_url)
            except Exception as error:
                discoveries.append(
                    Discovery(
                        kind="javascript_bundle_error",
                        data={
                            "url": script_url,
                            "error": str(error).strip() or error.__class__.__name__,
                            "source": self.metadata.name,
                        },
                    )
                )
                continue
            if not isinstance(content, str):
                continue
            for extracted in extract_javascript_bundle_observations(
                content, script_url, self._limits
            ):
                discoveries.append(
                    Discovery(
                        kind=f"javascript_{extracted['kind']}",
                        data={**extracted, "source_endpoint": script_url},
                    )
                )
        return discoveries
