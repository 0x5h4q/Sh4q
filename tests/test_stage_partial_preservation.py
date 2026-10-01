"""A stage cut off keeps what it already finished.

`discovered-dns`, `discovered-http`, `vhost-discovery` and
`directory-discovery` each catch their own cancellation and return what
completed. Three stages did not, and the scheduler's timeout path returns
`[]`, so their finished work was discarded:

- `http` gathers one probe per authorized origin, so a scope naming
  several ports loses every probe that had answered.
- `ct` gathers one query per provider, so a provider that had already
  returned names is lost when a slower one holds the stage past its
  deadline. The cache only helps on a *retry*; it cannot help if the
  results never leave `execute`.
- `javascript-bundles` fetches `max_bundles` scripts in a loop, one await
  each, and had already proved able to hit its deadline in production.

Two stages are deliberately left alone, and this file records why so the
omission is not read as an oversight:

- `javascript-extraction` has exactly one await, at the top. Either the
  provider returns and the rest of the stage is synchronous and
  uninterruptible, or nothing exists to keep.
- `httpx-fingerprint` is one atomic subprocess bounded by its own shorter
  timeout, which already reports `timed_out` as an adapter_execution
  discovery. There is no mid-flight partial state.
"""

import asyncio

from sh4q.config import Sh4qConfig
from sh4q.javascript_extraction import JavaScriptExtractionLimits
from sh4q.plugins.ct_connectors import CTConnector
from sh4q.plugins.ct_plugin import CTPlugin
from sh4q.plugins.http_plugin import HTTPPlugin
from sh4q.plugins.javascript_bundle_plugin import JavaScriptBundlePlugin
from sh4q.scope import ScopeEngine


async def cancel_after(coro_task, settle: float = 0.05):
    """Let a stage make progress, then cancel it as its deadline would."""
    for _ in range(400):
        await asyncio.sleep(0.005)
        if getattr(cancel_after, "ready", lambda: True)():
            break
    await asyncio.sleep(settle)
    coro_task.cancel()
    return await coro_task


async def http_stage() -> None:
    """One origin answers, the second hangs; the answer must survive."""
    answered: list[str] = []

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url):
            answered.append(url)
            if url.startswith("http://"):
                import httpx
                return httpx.Response(
                    200, headers={"content-type": "text/html"}, content="ok",
                    request=httpx.Request("GET", url),
                )
            await asyncio.sleep(3600)
            raise AssertionError("cancelled probe should not finish")

    scope = ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"], "ports": [80, 443]}))
    plugin = HTTPPlugin(scope, client_factory=Client)
    task = asyncio.create_task(plugin.execute("example.com"))
    for _ in range(400):
        await asyncio.sleep(0.005)
        if len(answered) >= 2:
            break
    task.cancel()
    results = await task
    kinds = [item.kind for item in results]
    assert any(k == "http_probe" for k in kinds), (
        f"the probe that answered was discarded: {kinds}"
    )


async def ct_stage() -> None:
    """One provider answers, the other hangs; its names must survive."""

    class Fast(CTConnector):
        name = "certspotter"

        async def fetch_hostnames(self, target, timeout):
            return [f"www.{target}", f"api.{target}"]

    class Hanging(CTConnector):
        name = "crt.sh"

        async def fetch_hostnames(self, target, timeout):
            await asyncio.sleep(3600)
            raise AssertionError("cancelled query should not finish")

    plugin = CTPlugin(connectors=[Fast(), Hanging()])
    task = asyncio.create_task(plugin.execute("example.com"))
    await asyncio.sleep(0.1)
    task.cancel()
    results = await task
    found = sorted(
        item.data["hostname"] for item in results if item.kind == "subdomain_found"
    )
    assert found == ["api.example.com", "www.example.com"], (
        f"the provider that answered was discarded: {found}"
    )


async def bundle_stage() -> None:
    """Bundles fetched before the deadline must survive it."""
    fetched: list[str] = []

    async def observations(target):
        return [{
            "endpoint": "https://example.com/",
            "content": '<script src="https://example.com/a.js"></script>'
                       '<script src="https://example.com/b.js"></script>',
        }]

    async def fetcher(url):
        fetched.append(url)
        if url.endswith("a.js"):
            return "fetch('/api/v1/first')"
        await asyncio.sleep(3600)
        raise AssertionError("cancelled fetch should not finish")

    plugin = JavaScriptBundlePlugin(
        observations, fetcher, limits=JavaScriptExtractionLimits(), max_bundles=2
    )
    task = asyncio.create_task(plugin.execute("example.com"))
    for _ in range(400):
        await asyncio.sleep(0.005)
        if len(fetched) >= 2:
            break
    task.cancel()
    results = await task
    assert results, "the bundle parsed before the deadline was discarded"
    assert any("first" in str(item.data.get("value", "")) for item in results), (
        f"expected the first bundle's observation, got {[r.data for r in results]}"
    )


async def completion_is_unaffected() -> None:
    """A stage that finishes normally behaves exactly as before."""

    class Fast(CTConnector):
        name = "certspotter"

        async def fetch_hostnames(self, target, timeout):
            return [f"www.{target}"]

    results = await CTPlugin(connectors=[Fast()]).execute("example.com")
    assert [i.kind for i in results].count("subdomain_found") == 1


async def main() -> None:
    await http_stage()
    await ct_stage()
    await bundle_stage()
    await completion_is_unaffected()
    print("stage partial preservation test passed")


asyncio.run(main())
