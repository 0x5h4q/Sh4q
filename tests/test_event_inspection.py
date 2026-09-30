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
    failed = Event(type="failed", payload={"scan_target": "example.com"})
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
    assert len(await log.list_records(target="example.com")) == 1
    summary = await log.summarize(target="example.com")
    assert len(summary) == 1
    assert summary[0].target == "example.com"
    assert summary[0].status == "DEAD_LETTER"
    assert summary[0].count == 1
    assert summary[0].retried == 1

    # --- a listing must be able to say how much of the log it is showing ----
    # `events --details --limit 10` printed ten rows out of 7179 for a real
    # database and said nothing about the other 7169, and `events` and `scans`
    # printed no count line at all.
    assert await log.count_records() == 2
    assert await log.count_groups() == 2
    # Every filter a listing accepts must count the same set the listing shows.
    for status, target in (
        (None, None),
        ("DEAD_LETTER", None),
        ("COMPLETED", None),
        (None, "example.com"),
        ("DEAD_LETTER", "example.com"),
        ("COMPLETED", "example.com"),
        ("PENDING", None),
        (None, "absent.example"),
    ):
        listed = await log.list_records(status=status, target=target, limit=None)
        grouped = await log.summarize(status=status, target=target, limit=None)
        assert await log.count_records(status=status, target=target) == len(listed), (
            f"record count disagrees with the listing for {status=} {target=}"
        )
        assert await log.count_groups(status=status, target=target) == len(grouped), (
            f"group count disagrees with the summary for {status=} {target=}"
        )
        # The counts inside the shown groups must account for every record the
        # same filter matches, or the coverage line the CLI prints is fiction.
        assert sum(row.count for row in grouped) == len(listed), (
            f"group counts do not sum to the record count for {status=} {target=}"
        )

    # A requested limit is honoured as asked; these clamped to 500 silently.
    assert len(await log.list_records(limit=1)) == 1
    assert len(await log.list_records(limit=None)) == 2
    assert len(await log.summarize(limit=1)) == 1
    assert len(await log.summarize(limit=None)) == 2

    print("event inspection test passed")


asyncio.run(main())
