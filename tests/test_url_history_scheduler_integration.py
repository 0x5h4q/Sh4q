"""Integration test: URL-history adapter through the scheduler pipeline."""

import asyncio

from sh4q.adapters.url_history import URLHistoryAdapter
from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine


async def main():
    config = Sh4qConfig(**{"scope": {"targets": ["example.com"]}})
    scope = ScopeEngine(config)

    adapter = URLHistoryAdapter(scope, max_urls=5000)

    urls = [
        "https://api.example.com/old?a=1",
        "https://evil.test/out",
    ]
    adapter._query_cdx = lambda domain: urls

    async def fake_query_cdx(domain):
        return urls
    adapter._query_cdx = fake_query_cdx
    discoveries = await adapter.execute("example.com")

    # Verify both URLs came through
    url_values = set()
    for d in discoveries:
        if d.kind == "url_history_batch":
            url_values.update(d.data["urls"])

    assert "https://api.example.com/old?a=1" in url_values
    assert "https://evil.test/out" in url_values

    # Verify discovery kinds
    kinds = {d.kind for d in discoveries}
    assert "url_history_batch" in kinds

    print("URL history scheduler integration test passed")


asyncio.run(main())
