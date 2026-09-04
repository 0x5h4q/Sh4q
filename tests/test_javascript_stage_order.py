import asyncio

from sh4q.config import Sh4qConfig
from sh4q.events import EventBus
from sh4q.plugins import Plugin, PluginMetadata
from sh4q.plugins.javascript_extraction_plugin import JavaScriptExtractionPlugin
from sh4q.scheduler import Scheduler
from sh4q.scope import ScopeEngine


order = []


class Stage(Plugin):
    def __init__(self, name, dependencies=None):
        self.metadata = PluginMetadata(name=name, dependencies=dependencies or [])

    async def execute(self, target):
        order.append(self.metadata.name)
        return []


async def provider(target):
    order.append("provider")
    return []


async def main():
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    scheduler = Scheduler(
        [
            JavaScriptExtractionPlugin(provider, after_discovered_http=True),
            Stage("discovered-http", ["http"]),
            Stage("http"),
        ],
        scope,
        EventBus(),
    )
    await scheduler.run("example.com")
    assert order == ["http", "discovered-http", "provider"]
    print("javascript stage order test passed")


asyncio.run(main())
