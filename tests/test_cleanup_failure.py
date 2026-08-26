import asyncio

from sh4q.events import EventBus
from sh4q.plugins import Discovery, Plugin, PluginMetadata
from sh4q.scheduler import Scheduler
from sh4q.scope import ScopeEngine
from sh4q.config import Sh4qConfig


class CleanupFailurePlugin(Plugin):
    metadata = PluginMetadata(name="cleanup_failure")

    async def execute(self, target: str) -> list[Discovery]:
        return [Discovery(kind="test", data={})]

    async def cleanup(self) -> None:
        raise RuntimeError("cleanup failed")


class HealthyPlugin(Plugin):
    metadata = PluginMetadata(name="healthy")
    ran = False

    async def execute(self, target: str) -> list[Discovery]:
        self.ran = True
        return []


async def main() -> None:
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    bus = EventBus()
    bus.start()
    healthy = HealthyPlugin()
    await Scheduler(
        plugins=[CleanupFailurePlugin(), healthy],
        scope=scope,
        bus=bus,
    ).run("example.com")
    await bus.drain()
    await bus.shutdown()
    assert healthy.ran
    print("cleanup failure isolation test passed")


asyncio.run(main())
