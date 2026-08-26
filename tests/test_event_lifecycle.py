import asyncio
import os

import aiosqlite

from sh4q.events import Event, EventBus
from sh4q.events.event_log import DurableEventLog


async def main() -> None:
    bus = EventBus()
    processed: list[str] = []

    async def broken(event: Event) -> None:
        raise RuntimeError("expected failure")

    async def healthy(event: Event) -> None:
        processed.append(event.id)

    bus.subscribe("broken", broken)
    bus.subscribe("healthy", healthy)
    bus.start()
    await bus.publish(Event(type="broken"))
    healthy_event = Event(type="healthy")
    await bus.publish(healthy_event)
    await asyncio.wait_for(bus.drain(), timeout=1)
    assert processed == [healthy_event.id]
    await bus.shutdown()
    assert bus._dispatcher_task is None

    path = "/tmp/sh4q_event_cancel_test.db"
    if os.path.exists(path):
        os.remove(path)
    log = DurableEventLog(path)
    await log.init()
    durable_bus = EventBus(event_log=log)
    started = asyncio.Event()

    async def slow(event: Event) -> None:
        started.set()
        await asyncio.Event().wait()

    durable_bus.subscribe("slow", slow)
    interrupted = Event(type="slow")
    queued = Event(type="slow")
    await durable_bus.publish(interrupted)
    await durable_bus.publish(queued)
    durable_bus.start()
    await asyncio.wait_for(started.wait(), timeout=1)
    await durable_bus.shutdown()

    async with aiosqlite.connect(path) as db:
        rows = dict(
            await (
                await db.execute(
                    "SELECT id, status FROM event_log WHERE id IN (?, ?)",
                    (interrupted.id, queued.id),
                )
            ).fetchall()
        )
    assert rows[interrupted.id] == "PROCESSING"
    assert rows[queued.id] == "PENDING"

    recovery_bus = EventBus(event_log=log)
    assert await recovery_bus.recover() == 2
    print("event lifecycle test passed")


asyncio.run(main())
