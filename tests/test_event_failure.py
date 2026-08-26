import asyncio
import os

import aiosqlite

from sh4q.events import Event, EventBus
from sh4q.events.event_log import DurableEventLog


async def main() -> None:
    path = "/tmp/sh4q_event_failure_test.db"
    if os.path.exists(path):
        os.remove(path)
    log = DurableEventLog(path)
    await log.init()
    bus = EventBus(event_log=log)

    async def broken(event: Event) -> None:
        raise RuntimeError("deliberate handler failure")

    bus.subscribe("test", broken)
    event = Event(type="test")
    await bus.publish(event)
    bus.start()
    await asyncio.wait_for(bus.drain(), timeout=1)
    bus.stop()

    async with aiosqlite.connect(path) as db:
        row = await (
            await db.execute(
                "SELECT status, error FROM event_log WHERE id = ?",
                (event.id,),
            )
        ).fetchone()
    assert row[0] == "FAILED"
    assert "deliberate handler failure" in row[1]
    print("event failure recovery test passed")


asyncio.run(main())
