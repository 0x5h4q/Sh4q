import asyncio
import contextlib
import io

from sh4q.config import Sh4qConfig
from sh4q.events import EventBus
from sh4q.plugins import Plugin, PluginMetadata
from sh4q.scheduler import Scheduler
from sh4q.scope import ScopeEngine


class SlowPlugin(Plugin):
    metadata = PluginMetadata(name="slow", version="test", timeout=8.0)

    async def execute(self, target):
        await asyncio.sleep(5.2)
        return []


async def main():
    output = io.StringIO()
    bus = EventBus()
    bus.start()
    with contextlib.redirect_stdout(output):
        await Scheduler([SlowPlugin()], ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}})), bus).run("example.com")
    await bus.shutdown()
    assert "IN PROGRESS slow on example.com (elapsed 5s)" in output.getvalue()
    print("scheduler progress test passed")


asyncio.run(main())
