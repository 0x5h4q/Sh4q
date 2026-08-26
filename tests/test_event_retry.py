import asyncio
import os
import aiosqlite

from sh4q.events import Event, EventBus
from sh4q.events.event_log import DurableEventLog


async def main() -> None:
    path = "/tmp/sh4q_event_retry_test.db"
    if os.path.exists(path):
        os.remove(path)
    log = DurableEventLog(path)
    await log.init()
    calls = 0
    bus = EventBus(event_log=log, max_event_attempts=2)

    async def broken(event: Event) -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("retry me")

    bus.subscribe("test", broken)
    event = Event(type="test")
    await bus.publish(event)
    bus.start()
    await bus.drain()
    bus.stop()
    assert calls == 1

    retry_bus = EventBus(event_log=log, max_event_attempts=2)
    retry_bus.subscribe("test", broken)
    assert await retry_bus.recover() == 1
    retry_bus.start()
    await retry_bus.drain()
    retry_bus.stop()

    async with aiosqlite.connect(path) as db:
        row = await (await db.execute("SELECT status, attempts FROM event_log WHERE id = ?", (event.id,))).fetchone()
    assert row == ("DEAD_LETTER", 2)
    assert calls == 2
    print("event retry and dead-letter test passed")


asyncio.run(main())
