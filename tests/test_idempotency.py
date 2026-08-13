import asyncio
import os
from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine
from sh4q.storage import SQLiteStorage
from sh4q.storage.evidence import SQLiteEvidenceStore
from sh4q.events import Event, EventBus
from sh4q.events.event_log import DurableEventLog
from sh4q.handlers import make_discovery_handler


async def main():
    db_path = "/tmp/sh4q_replay_idempotency_test.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    cfg = Sh4qConfig(**{"scope": {"targets": ["example.com", "10.0.0.0/24"]}})
    scope = ScopeEngine(cfg)
    storage = SQLiteStorage(db_path)
    await storage.init()
    evidence_store = SQLiteEvidenceStore(db_path)
    await evidence_store.init()
    event_log = DurableEventLog(db_path)
    await event_log.init()
    handler = make_discovery_handler(scope, storage, evidence_store)

    event = Event(type="discovery", payload={
        "kind": "dns_resolution",
        "data": {"domain": "example.com", "ip": "10.0.0.55"},
        "source_plugin": "dns",
    })

    print("=== Simulate the WORST crash: work done, crash BEFORE mark_completed ===")
    await event_log.record_pending(event)
    await event_log.mark_processing(event.id)
    await handler(event)
    print("  handler ran: node + relationship + evidence saved, then 'crash'")

    node_before = await storage.get_node("ip:10.0.0.55")
    rels_before = await storage.get_relationships("domain:example.com")
    evidence_before = await evidence_store.get(event.id)

    print()
    print("=== NEW PROCESS — recovers and reprocesses the SAME event ===")
    new_bus = EventBus(event_log=event_log)
    new_bus.subscribe("discovery", handler)
    recovered = await new_bus.recover()
    print(f"  recovered {recovered} event(s)")
    new_bus.start()
    await new_bus.drain()
    new_bus.stop()

    print()
    node_after = await storage.get_node("ip:10.0.0.55")
    rels_after = await storage.get_relationships("domain:example.com")

    print(f"  relationship count: before={len(rels_before)}, after={len(rels_after)} (must match)")
    print(f"  node first_seen unchanged: {node_before.first_seen == node_after.first_seen}")

    import aiosqlite
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM evidence WHERE id = ?", (event.id,))
        count = (await cursor.fetchone())[0]
        print(f"  actual evidence row count: {count} (must be exactly 1)")


asyncio.run(main())