"""A stage that reported truncation is not recorded as completed.

A real scan contacted 72 of 164 hosts. The stage said so at the time --
`INCOMPLETE discovered-http reached 72 of 164 host(s)` -- and the
truncation record went into evidence. But `stage_metrics` recorded:

    {'name': 'discovered-http', 'status': 'completed', 'discoveries': 198}

So the durable record said completed over a stage that reached 44% of its
hosts, and `sh4q show` repeated it. Reading that scan a week later, the
Stages table is the account of what happened, and it was wrong.

The stage cannot fix this itself. It swallows its own cancellation
deliberately -- that is what preserves the partial results -- so the
scheduler sees a normal return. But the stage does say what happened, in
the discoveries it returns, and the scheduler already inspects those for
retryable failures. It can read the truncation the same way.
"""

import asyncio
import contextlib
import io

from sh4q.config import Sh4qConfig
from sh4q.events import EventBus
from sh4q.plugins import Discovery, Plugin, PluginMetadata
from sh4q.scheduler import Scheduler
from sh4q.scope import ScopeEngine


class TruncatingPlugin(Plugin):
    """Returns real results plus the truncation record, as the real stages do."""

    metadata = PluginMetadata(name="discovered-http", version="test", timeout=5.0)

    async def execute(self, target):
        return [
            Discovery("http_probe", {"final_url": f"https://{target}/", "status": 200}),
            Discovery("discovered_http_truncated", {"total": 164, "reached": 72, "not_reached": 92}),
        ]


class CleanPlugin(Plugin):
    metadata = PluginMetadata(name="clean", version="test", timeout=5.0)

    async def execute(self, target):
        return [Discovery("http_probe", {"final_url": f"https://{target}/", "status": 200})]


async def outcome_for(plugin):
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    bus = EventBus()
    bus.start()
    scheduler = Scheduler([plugin], scope, bus)
    with contextlib.redirect_stdout(io.StringIO()) as captured:
        await scheduler.run("example.com")
    await bus.shutdown()
    return scheduler.stage_outcomes[plugin.metadata.name], captured.getvalue()


async def main() -> None:
    truncated, text = await outcome_for(TruncatingPlugin())
    assert truncated["status"] != "completed", (
        f"a stage that reported truncation is not complete: {truncated}"
    )
    assert truncated["status"] == "truncated", truncated
    # The results it kept are still its findings, not discarded.
    assert truncated["discoveries"] == 2, truncated
    assert "STAGE COMPLETE discovered-http" not in text, text

    clean, clean_text = await outcome_for(CleanPlugin())
    assert clean["status"] == "completed", clean
    assert "STAGE COMPLETE clean" in clean_text, clean_text

    # Every stage that can truncate is recognised, not just the one that
    # exposed this.
    for kind in ("discovered_dns_truncated", "directory_truncated",
                 "url_history_truncated", "discovered_http_truncated"):
        class Marked(Plugin):
            metadata = PluginMetadata(name=f"s-{kind}", version="test", timeout=5.0)

            async def execute(self, target, _kind=kind):
                return [Discovery(_kind, {"total": 10, "reached": 1, "not_reached": 9})]

        result, _ = await outcome_for(Marked())
        assert result["status"] == "truncated", f"{kind}: {result}"

    print("truncated stage status test passed")


asyncio.run(main())
