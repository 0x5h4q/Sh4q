import asyncio

import httpx

from sh4q.config import Sh4qConfig
from sh4q.plugins import Discovery
from sh4q.plugins.discovered_http_plugin import DiscoveredHTTPPlugin
from sh4q.scope import ScopeEngine


class FakeClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return None

    async def get(self, url):
        request = httpx.Request("GET", url)
        return httpx.Response(200, request=request, headers={"server": "test"})


async def main():
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    plugin = DiscoveredHTTPPlugin(
        scope,
        max_names=2,
        max_concurrent=1,
        client_factory=FakeClient,
    )
    plugin.accept_discoveries(
        [
            Discovery("discovered_dns_resolution", {"domain": "API.EXAMPLE.COM.", "ip": "93.184.216.34"}),
            Discovery("discovered_dns_resolution", {"domain": "api.example.com", "ip": "93.184.216.35"}),
            Discovery("discovered_dns_error", {"domain": "dead.example.com"}),
            Discovery("discovered_dns_resolution", {"domain": "evil.test", "ip": "93.184.216.34"}),
        ],
        "discovered-dns",
    )
    assert plugin._names == ["api.example.com"]
    results = await plugin.execute("example.com")
    probes = [item for item in results if item.kind == "http_probe"]
    assert {item.data["final_url"] for item in probes} == {
        "http://api.example.com",
        "https://api.example.com",
    }
    print("discovered HTTP plugin test passed")


asyncio.run(main())
