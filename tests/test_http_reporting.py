import asyncio

from sh4q.config import Sh4qConfig
from sh4q.plugins.http_plugin import HTTPPlugin
from sh4q.scope import ScopeEngine


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
                "headers": {"server": "fake"},
            })()
        await asyncio.sleep(0.05)
        raise asyncio.TimeoutError


async def main() -> None:
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    plugin = HTTPPlugin(scope, client_factory=FakeClient)
    discoveries = await plugin.execute("example.com")
    assert any(item.kind == "http_probe" and item.data["status"] == 200 for item in discoveries)
    assert any(item.kind == "http_error" and item.data["url"] == "http://example.com" for item in discoveries)
    print("HTTP per-scheme reporting test passed")


asyncio.run(main())
