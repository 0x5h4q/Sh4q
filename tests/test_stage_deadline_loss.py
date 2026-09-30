"""A stage cut off at its deadline keeps its work and says it was cut off.

`discovered-http` already does this, and `test_discovered_http_timeout.py`
guards it. Two stages did not.

Directory discovery sleeps one second between candidates and carries a
900s deadline with `retry_on_timeout=False`, so the deadline is reachable
and a timeout is terminal. `execute` had no `CancelledError` handler, so
every observation it had already made -- each one a request actually sent
to the target -- was discarded on the way out. The cost of the sweep was
paid and the result thrown away.

The `javascript-bundles` deadline was the fixed 45s of a class attribute
while the work is `max_bundles` fetches over a rate-limited client. On a
real scan it timed out and was retried, which spends the budget twice for
the same reason.
"""

import asyncio
import tempfile
from pathlib import Path

import httpx

from sh4q.config import Sh4qConfig
from sh4q.javascript_extraction import JavaScriptExtractionLimits
from sh4q.plugins import DirectoryDiscoveryPlugin
from sh4q.plugins.javascript_bundle_plugin import JavaScriptBundlePlugin
from sh4q.scope import ScopeEngine


def scope_for(target: str) -> ScopeEngine:
    return ScopeEngine(Sh4qConfig(scope={"targets": [target], "ports": [443]}))


class CountingClient:
    """Answers a fixed number of probes, then blocks forever.

    The block stands in for a slow server: it is what leaves the stage
    holding completed observations when the deadline arrives.
    """

    def __init__(self, answer_count: int):
        self.answer_count = answer_count
        self.urls: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get_text_bounded(self, url, max_bytes, **kwargs):
        self.urls.append(url)
        if len(self.urls) > self.answer_count:
            await asyncio.sleep(3600)
            raise AssertionError("cancelled probe should not finish")
        body = "admin page" if url.endswith("/admin") else "not found"
        status = 200 if url.endswith("/admin") else 404
        response = httpx.Response(
            status,
            headers={"content-type": "text/html"},
            content=body,
            request=httpx.Request("GET", url),
        )
        return response, body, False


def candidate_file(directory: str, paths: list[str]) -> str:
    path = Path(directory) / "paths.txt"
    path.write_text("\n".join(paths) + "\n", encoding="utf-8")
    return str(path)


async def directory_cancellation() -> None:
    paths = ["/admin", "/backup", "/config", "/private", "/secret"]
    with tempfile.TemporaryDirectory() as directory:
        # Two baseline probes plus /admin answer; the sweep then blocks.
        client = CountingClient(answer_count=3)
        plugin = DirectoryDiscoveryPlugin(
            scope_for("example.com"),
            candidate_file(directory, paths),
            client_factory=lambda: client,
        )
        task = asyncio.create_task(plugin.execute("example.com"))
        # The plugin sleeps 1s between candidates, so allow the first to land.
        for _ in range(200):
            await asyncio.sleep(0.01)
            if len(client.urls) >= 4:
                break
        task.cancel()
        results = await task

    kinds = [item.kind for item in results]
    assert results, "a cancelled sweep must not discard everything it found"

    # The work already done survives: the baseline and the /admin hit.
    assert "directory_baseline" in kinds, kinds
    observed = [
        item for item in results
        if item.kind == "directory_observation" and item.data.get("path") == "/admin"
    ]
    assert observed, f"the completed /admin observation was lost: {kinds}"
    assert observed[0].data["classification"] == "candidate_observation", observed[0].data

    # And the stage says it was cut off, with an accurate count. Without this
    # the scheduler records a clean completion, because a suppressed
    # cancellation never reaches asyncio.wait_for.
    truncations = [item for item in results if item.kind == "directory_truncated"]
    assert len(truncations) == 1, kinds
    record = truncations[0].data
    assert record["total"] == len(paths), record
    assert record["swept"] + record["not_swept"] == len(paths), record
    assert record["swept"] >= 1, record
    assert record["not_swept"] >= 1, record


async def directory_completion() -> None:
    """A sweep that finishes must not claim it was cut off."""
    with tempfile.TemporaryDirectory() as directory:
        client = CountingClient(answer_count=1000)
        plugin = DirectoryDiscoveryPlugin(
            scope_for("example.com"),
            candidate_file(directory, ["/admin"]),
            client_factory=lambda: client,
        )
        results = await plugin.execute("example.com")
    assert not any(item.kind == "directory_truncated" for item in results), (
        "a completed sweep must not report truncation"
    )
    assert any(
        item.kind == "directory_observation" and item.data.get("path") == "/admin"
        for item in results
    )


def bundle_deadline() -> None:
    """The deadline has to grow with the work the stage was asked to do."""

    async def no_observations(target):
        return []

    async def fetcher(url):
        return ""

    def plugin_for(**kwargs) -> JavaScriptBundlePlugin:
        return JavaScriptBundlePlugin(
            no_observations, fetcher, limits=JavaScriptExtractionLimits(), **kwargs
        )

    small = plugin_for(max_bundles=1).metadata.timeout
    default = plugin_for().metadata.timeout
    large = plugin_for(max_bundles=60).metadata.timeout

    assert default > small, (
        f"ten bundles must not share a deadline with one: {default} vs {small}"
    )
    assert large > default * 2, (
        f"sixty bundles need far longer than ten: {large} vs {default}"
    )
    # The published 45s floor stays a floor, so a small stage is not made
    # slower to fail than it was.
    assert small >= 45.0, small

    # A slower request rate means the same work takes longer, so the deadline
    # must account for it rather than assuming the default.
    class Limiter:
        def __init__(self, rate):
            self.requests_per_second = rate

    fast = JavaScriptBundlePlugin(
        no_observations, fetcher, max_bundles=60, limiter=Limiter(10.0)
    ).metadata.timeout
    slow = JavaScriptBundlePlugin(
        no_observations, fetcher, max_bundles=60, limiter=Limiter(0.5)
    ).metadata.timeout
    assert slow > fast, f"a slower rate needs a longer deadline: {slow} vs {fast}"


async def main() -> None:
    await directory_cancellation()
    await directory_completion()
    bundle_deadline()
    print("stage deadline loss test passed")


asyncio.run(main())
