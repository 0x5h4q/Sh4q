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


async def main():
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    plugin = DiscoveredHTTPPlugin(scope, max_names=1, client_factory=SlowClient)
    plugin.accept_discoveries([
        Discovery("discovered_dns_resolution", {"domain": "api.example.com", "ip": "93.184.216.34"})
    ], "discovered-dns")
    task = asyncio.create_task(plugin.execute("example.com"))
    await asyncio.sleep(0.02)
    task.cancel()
    results = await task
    assert results == []
    print("discovered HTTP timeout preservation test passed")


asyncio.run(main())
