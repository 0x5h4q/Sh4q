import asyncio
import os

from sh4q.events import Event
from sh4q.events.event_log import DurableEventLog


async def main() -> None:
    path = "/tmp/sh4q_event_inspection_test.db"
    if os.path.exists(path):
        os.remove(path)
    log = DurableEventLog(path)
    await log.init()
    failed = Event(type="failed")
    completed = Event(type="completed")
    await log.record_pending(failed)
    await log.mark_failed(failed.id, "deliberate", max_attempts=1)
    await log.record_pending(completed)
    await log.mark_completed(completed.id)

    dead_letters = await log.list_records(status="DEAD_LETTER")
    assert len(dead_letters) == 1
    assert dead_letters[0].id == failed.id
    assert dead_letters[0].error == "deliberate"
    assert len(await log.list_records()) == 2
    print("event inspection test passed")


asyncio.run(main())
