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
        status = 403 if "blocked.example.com" in url else 200
        return httpx.Response(status, request=request, headers={"server": "test"})


class DelayedFakeClient(FakeClient):
    async def get(self, url):
        await asyncio.sleep(0.1)
        return await super().get(url)


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
            Discovery("discovered_dns_resolution", {"domain": "blocked.example.com", "ip": "93.184.216.36"}),
            Discovery("discovered_dns_error", {"domain": "dead.example.com"}),
            Discovery("discovered_dns_resolution", {"domain": "evil.test", "ip": "93.184.216.34"}),
        ],
        "discovered-dns",
    )
    assert plugin._names == ["api.example.com", "blocked.example.com"]
    assert plugin._addresses["api.example.com"] == {"93.184.216.34", "93.184.216.35"}
    results = await plugin.execute("example.com")
    probes = [item for item in results if item.kind == "http_probe"]
    assert {item.data["final_url"] for item in probes} == {
        "http://api.example.com",
        "https://api.example.com",
        "http://blocked.example.com",
        "https://blocked.example.com",
    }
    assert {item.data["status"] for item in probes} == {200, 403}
    assert all("dead.example.com" not in item.data["final_url"] for item in probes)
    assert all("evil.test" not in item.data["final_url"] for item in probes)

    from sh4q.plugins.http_plugin import HTTPPlugin
    original_timeout = HTTPPlugin.metadata.timeout
    try:
        HTTPPlugin.metadata.timeout = 0.05
        queued = DiscoveredHTTPPlugin(scope, max_names=1, client_factory=DelayedFakeClient)
        queued.accept_discoveries(
            [Discovery("discovered_dns_resolution", {"domain": "api.example.com", "ip": "93.184.216.34"})],
            "discovered-dns",
        )
        queued_results = await queued.execute("example.com")
        assert len([item for item in queued_results if item.kind == "http_probe"]) == 2
    finally:
        HTTPPlugin.metadata.timeout = original_timeout
    print("discovered HTTP plugin test passed")


asyncio.run(main())
