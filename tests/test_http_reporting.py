import asyncio

from sh4q.config import Sh4qConfig
from sh4q.plugins.http_plugin import HTTPPlugin
from sh4q.scope import ScopeEngine
from sh4q.handlers import _canonical_url


class FakeClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, url: str):
        if url.startswith("https://"):
            return type("Response", (), {
                "url": url,
                "status_code": 200,
                "headers": {"server": "nginx/1.25", "x-powered-by": "Express"},
            })()
        await asyncio.sleep(0.05)
        raise asyncio.TimeoutError


class SlowClient(FakeClient):
    async def get(self, url: str):
        await asyncio.sleep(1)


async def main() -> None:
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    plugin = HTTPPlugin(scope, client_factory=FakeClient)
    discoveries = await plugin.execute("example.com")
    assert any(item.kind == "http_probe" and item.data["status"] == 200 for item in discoveries)
    fingerprints = [item for item in discoveries if item.kind == "http_fingerprint"]
    assert {item.data["technologies"][0] for item in fingerprints} == {"nginx", "Express"}
    assert {item.data["detection_method"] for item in fingerprints} == {"native-signature"}
    assert any(item.kind == "http_error" and item.data["url"] == "http://example.com" for item in discoveries)
    assert _canonical_url("https://Example.com:443/") == "https://example.com/"
    assert _canonical_url("http://example.com:8080/a///?x=1") == "http://example.com:8080/a?x=1"

    original_timeout = HTTPPlugin.metadata.timeout
    try:
        slow_plugin = HTTPPlugin(scope, client_factory=SlowClient)
        slow_plugin.metadata.timeout = 0.2
        slow = await slow_plugin.execute("example.com")
        assert len([item for item in slow if item.kind == "http_error"]) == 2
        assert all(item.data["phase"] == "overall" for item in slow)
    finally:
        HTTPPlugin.metadata.timeout = original_timeout
    print("HTTP per-scheme reporting test passed")


asyncio.run(main())
