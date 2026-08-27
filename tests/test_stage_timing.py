import asyncio

from sh4q.config import Sh4qConfig
from sh4q.events import EventBus
from sh4q.plugins import Plugin, PluginMetadata
from sh4q.scheduler import Scheduler
from sh4q.scope import ScopeEngine


class TimedPlugin(Plugin):
    metadata = PluginMetadata(name="timed")

    async def execute(self, target):
        await asyncio.sleep(0.01)
        return []


async def main():
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    bus = EventBus()
    bus.start()
    scheduler = Scheduler([TimedPlugin()], scope, bus)
    try:
        await scheduler.run("example.com")
    finally:
        await bus.shutdown()
    assert scheduler.stage_durations["timed"] >= 0.01
    print("stage timing test passed")


asyncio.run(main())
