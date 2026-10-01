from __future__ import annotations

import asyncio

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

    #: The floor the stage published before its deadline scaled. Kept as a
    #: floor so a one-bundle stage is not made quicker to fail than it was.
    MINIMUM_TIMEOUT = 45.0

    metadata = PluginMetadata(
        name="javascript-bundles",
        dependencies=["javascript-extraction"],
        risk_level="active-low",
        timeout=MINIMUM_TIMEOUT,
    )

    def __init__(
        self,
        observations_provider: Callable[[str], Awaitable[list[dict]]],
        bundle_fetcher: Callable[[str], Awaitable[str | None]],
        limits: JavaScriptExtractionLimits | None = None,
        max_bundles: int = 10,
        limiter=None,
        per_request_timeout: float = 10.0,
    ):
        self._observations_provider = observations_provider
        self._bundle_fetcher = bundle_fetcher
        self._limits = limits or JavaScriptExtractionLimits()
        self._max_bundles = max(1, max_bundles)

        # A whole-stage deadline has to scale with the work the stage was
        # asked to do. The class attribute was a flat 45s while the work is
        # `max_bundles` rate-limited fetches, each able to spend the full
        # per-request timeout: on a real scan the stage hit the deadline and
        # was retried, which spends the request budget twice over for the
        # same reason it failed the first time.
        rate = getattr(limiter, "requests_per_second", None) or 2.0
        per_fetch = 1.0 / max(rate, 0.1) + max(0.1, per_request_timeout)
        self.metadata = PluginMetadata(
            name=type(self).metadata.name,
            dependencies=list(type(self).metadata.dependencies),
            risk_level=type(self).metadata.risk_level,
            timeout=max(
                self.MINIMUM_TIMEOUT, self._max_bundles * per_fetch * 1.2 + 15.0
            ),
        )

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
            except asyncio.CancelledError:
                # One await per bundle, so the deadline lands mid-loop and the
                # bundles already parsed are real work. The scheduler's timeout
                # path returns [] for a stage that lets the cancellation
                # through, so returning here is what keeps them -- but only
                # when there is something to keep. An empty return would claim
                # the stage completed and found nothing.
                if not discoveries:
                    raise
                return discoveries
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
