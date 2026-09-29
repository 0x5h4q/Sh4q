"""A cut-off HTTP stage keeps its results and says it was cut off.

The stage caught its own cancellation, returned whatever had completed,
and returned normally -- so asyncio.wait_for never raised, and the
scheduler recorded a clean completion. A real scan resolved 171 names,
contacted 109, and reported success. The 63 hosts it never reached were
invisible in the summary, in the stage metrics, and in the evidence.

Preserving partial results is right. Reporting them as a whole scan is
not.
"""

import asyncio

from sh4q.config import Sh4qConfig
from sh4q.plugins import Discovery
from sh4q.plugins.discovered_http_plugin import DiscoveredHTTPPlugin
from sh4q.scope import ScopeEngine


class SlowClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, url):
        await asyncio.sleep(1)
        raise AssertionError("cancelled probe should not finish")


def plugin_for(names: list[str], **kwargs) -> DiscoveredHTTPPlugin:
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    plugin = DiscoveredHTTPPlugin(scope, client_factory=SlowClient, **kwargs)
    plugin.accept_discoveries(
        [Discovery("discovered_dns_resolution", {"domain": n, "ip": "93.184.216.34"}) for n in names],
        "discovered-dns",
    )
    return plugin


async def main() -> None:
    # One name, cancelled before it finishes: no probe result, but the
    # truncation is on the record.
    plugin = plugin_for(["api.example.com"], max_names=1)
    task = asyncio.create_task(plugin.execute("example.com"))
    await asyncio.sleep(0.02)
    task.cancel()
    results = await task

    kinds = [item.kind for item in results]
    assert kinds == ["discovered_http_truncated"], kinds
    record = results[0].data
    assert record["total"] == 1, record
    assert record["reached"] == 0, record
    assert record["not_reached"] == 1, record
    assert not any(item.kind == "http_probe" for item in results), "no probe completed"

    # Several names: the count of hosts never contacted must be accurate,
    # because that number is the difference between a partial scan and a
    # scan that looks complete.
    names = [f"h{i}.example.com" for i in range(9)]
    plugin = plugin_for(names, max_names=9)
    task = asyncio.create_task(plugin.execute("example.com"))
    await asyncio.sleep(0.02)
    task.cancel()
    results = await task
    record = next(item.data for item in results if item.kind == "discovered_http_truncated")
    assert record["total"] == len(names), record
    assert record["reached"] + record["not_reached"] == len(names), record

    # A stage that finishes normally reports no truncation at all.
    class InstantClient(SlowClient):
        async def get(self, url):
            raise RuntimeError("probe failed fast")

    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    quick = DiscoveredHTTPPlugin(scope, max_names=2, client_factory=InstantClient)
    quick.accept_discoveries(
        [Discovery("discovered_dns_resolution", {"domain": "a.example.com", "ip": "1.2.3.4"})],
        "discovered-dns",
    )
    finished = await quick.execute("example.com")
    assert not any(item.kind == "discovered_http_truncated" for item in finished), (
        "a completed stage must not claim it was cut off"
    )

    print("discovered HTTP timeout preservation test passed")


asyncio.run(main())
