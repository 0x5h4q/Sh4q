"""The line that closes a stage must agree with the stage's recorded outcome.

"STAGE COMPLETE" was printed unconditionally, so on a real target the
terminal showed:

    [-] RETRY EXHAUSTED ct on <target> after 3 attempts

    [+] STAGE COMPLETE ct

The stage had in fact kept 184 names from the provider that succeeded, and
the durable outcome already said `retry_exhausted` -- the jsonl progress
event beside this print reads it. Only the human-facing line disagreed,
and it disagreed in the direction that hides a problem.
"""

import asyncio
import contextlib
import io

from sh4q.config import Sh4qConfig
from sh4q.events import EventBus
from sh4q.plugins import Discovery, Plugin, PluginMetadata
from sh4q.scheduler import Scheduler
from sh4q.scope import ScopeEngine


class CleanPlugin(Plugin):
    metadata = PluginMetadata(name="clean", version="test", timeout=5.0)

    async def execute(self, target):
        return [Discovery("dns_resolution", {"domain": target, "ip": "93.184.216.34"})]


class AlwaysRetryablePlugin(Plugin):
    """Keeps returning a retryable discovery, so retries are exhausted.

    It still returns a usable result each time, which is the case that made
    the old line wrong rather than merely imprecise.
    """

    metadata = PluginMetadata(name="flapping", version="test", timeout=5.0)

    def __init__(self):
        self.calls = 0

    async def execute(self, target):
        self.calls += 1
        return [
            Discovery("dns_resolution", {"domain": target, "ip": "93.184.216.34"}),
            Discovery("dns_error", {"domain": target, "error": "SERVFAIL", "retryable": True}),
        ]


class FailingPlugin(Plugin):
    metadata = PluginMetadata(name="broken", version="test", timeout=5.0)

    async def execute(self, target):
        raise RuntimeError("no")


def scope():
    return ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))


async def render(plugin) -> str:
    bus = EventBus()
    bus.start()
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        await Scheduler([plugin], scope(), bus).run("example.com")
    await bus.shutdown()
    return output.getvalue()


async def main() -> None:
    clean = await render(CleanPlugin())
    assert "STAGE COMPLETE clean" in clean, clean

    flapping = AlwaysRetryablePlugin()
    exhausted = await render(flapping)
    assert flapping.calls == 3, f"retries must actually be exhausted: {flapping.calls}"
    assert "RETRY EXHAUSTED flapping" in exhausted, exhausted
    assert "STAGE COMPLETE flapping" not in exhausted, (
        "a stage that exhausted its retries did not complete:\n" + exhausted
    )
    assert "STAGE INCOMPLETE flapping" in exhausted, exhausted
    # The results it did keep are stated, so the line is not merely a warning.
    assert "kept 2 result(s)" in exhausted, exhausted

    broken = await render(FailingPlugin())
    assert "STAGE COMPLETE broken" not in broken, broken
    assert "STAGE FAILED broken" in broken, broken

    print("stage outcome line test passed")


asyncio.run(main())
