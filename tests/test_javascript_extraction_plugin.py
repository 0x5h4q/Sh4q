import asyncio

from sh4q.plugins.javascript_extraction_plugin import JavaScriptExtractionPlugin


async def observations_provider(target: str) -> list[dict]:
    assert target == "example.com"
    return [
        {
            "endpoint": "https://example.com/app",
            "content": "<script src='/static/app.js'></script><script>fetch('/api/me')</script>",
        }
    ]


async def main() -> None:
    discoveries = await JavaScriptExtractionPlugin(observations_provider).execute("example.com")
    assert {item.kind for item in discoveries} == {
        "javascript_script_url",
        "javascript_endpoint_reference",
    }
    assert all(item.data["source_endpoint"] == "https://example.com/app" for item in discoveries)

    fetched: list[str] = []

    async def fetcher(url: str) -> str:
        fetched.append(url)
        return "fetch('/api/bundle');"

    from sh4q.plugins.javascript_bundle_plugin import JavaScriptBundlePlugin

    bundle_discoveries = await JavaScriptBundlePlugin(
        observations_provider,
        fetcher,
        max_bundles=2,
    ).execute("example.com")
    assert fetched == ["https://example.com/static/app.js"]
    assert [item.kind for item in bundle_discoveries] == ["javascript_endpoint_reference"]
    assert bundle_discoveries[0].data["source_endpoint"] == "https://example.com/static/app.js"
    print("javascript extraction plugin test passed")


asyncio.run(main())
