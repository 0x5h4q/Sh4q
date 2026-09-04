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
    print("javascript extraction plugin test passed")


asyncio.run(main())
