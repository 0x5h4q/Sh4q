import asyncio
import os
import time

import aiosqlite

from sh4q.events import Event
from sh4q.events.event_log import DurableEventLog
from sh4q.storage import Node, Relationship, SQLiteStorage
from sh4q.storage.evidence import Evidence, SQLiteEvidenceStore


async def main() -> None:
    path = "/tmp/sh4q_sqlite_concurrency_test.db"
    if os.path.exists(path):
        os.remove(path)
    storage = SQLiteStorage(path)
    evidence = SQLiteEvidenceStore(path)
    log = DurableEventLog(path)
    await storage.init()
    await evidence.init()
    await log.init()

    async def write(index: int) -> None:
        domain = Node(type="domain", value=f"host-{index}.example.com")
        ip = Node(type="ip", value=f"192.0.2.{(index % 200) + 1}")
        await storage.save_node(domain)
        await storage.save_node(ip)
        await storage.save_relationship(Relationship(domain.id, ip.id, "RESOLVES_TO"))
        event = Event(type="discovery", payload={"scan_target": "example.com", "kind": "test", "data": {"index": index}})
        await log.record_pending(event)
        await evidence.append(Evidence(event.id, "example.com", "test", "test", {"index": index}))

    started = time.monotonic()
    await asyncio.gather(*(write(index) for index in range(50)))
    duration = time.monotonic() - started

    async with aiosqlite.connect(path) as db:
        counts = {}
        for table in ("nodes", "relationships", "event_log", "evidence"):
            counts[table] = (await (await db.execute(f"SELECT COUNT(*) FROM {table}")).fetchone())[0]
    assert counts["nodes"] == 100
    assert counts["relationships"] == 50
    assert counts["event_log"] == 50
    assert counts["evidence"] == 50
    print(f"SQLite concurrency test passed ({duration:.3f}s): {counts}")


asyncio.run(main())
