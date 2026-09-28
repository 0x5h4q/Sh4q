"""Replaying an event must not duplicate anything it already persisted.

With a durable event log, delivery is at-least-once: an event interrupted
between doing its work and being marked complete is re-queued and handled
again on the next run. Every write the handler performs therefore has to
be safe to repeat.

This file previously printed its observations -- including the lines
"(must match)" and "(must be exactly 1)" -- and asserted nothing, so it
passed whether or not a replay duplicated rows. It is the guard for the
handler's persistence paths, so it now asserts.
"""

import asyncio
import os
import tempfile

import aiosqlite

from sh4q.config import Sh4qConfig
from sh4q.events import Event, EventBus
from sh4q.events.event_log import DurableEventLog
from sh4q.handlers import make_discovery_handler
from sh4q.scope import ScopeEngine
from sh4q.storage import SQLiteStorage
from sh4q.storage.evidence import SQLiteEvidenceStore


async def row_count(db_path: str, sql: str, *params) -> int:
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(sql, params)
        return (await cursor.fetchone())[0]


async def main() -> None:
    handle, db_path = tempfile.mkstemp(prefix="sh4q_replay_idempotency_", suffix=".db")
    os.close(handle)
    os.remove(db_path)
    try:
        scope = ScopeEngine(Sh4qConfig(scope={
            "targets": ["example.com", "10.0.0.0/24"],
            "allow_private_addresses": True,
        }))
        storage = SQLiteStorage(db_path)
        await storage.init()
        evidence_store = SQLiteEvidenceStore(db_path)
        await evidence_store.init()
        event_log = DurableEventLog(db_path)
        await event_log.init()

        stats: dict = {}
        handler = make_discovery_handler(scope, storage, evidence_store, stats=stats)

        event = Event(type="discovery", payload={
            "kind": "dns_resolution",
            "data": {"domain": "example.com", "ip": "10.0.0.55"},
            "source_plugin": "dns",
        })

        # The worst crash: the handler finished its work, then the process died
        # before the event could be marked complete.
        await event_log.record_pending(event)
        await event_log.mark_processing(event.id)
        await handler(event)

        node_before = await storage.get_node("ip:10.0.0.55")
        assert node_before is not None, "the first pass must persist the address"
        relationships_before = await storage.get_relationships("domain:example.com")
        assert len(relationships_before) == 1, relationships_before
        assert await evidence_store.get(event.id) is not None, "evidence must be written"
        assets_before = stats.get("discoveries")
        relationship_total_before = stats.get("relationships")

        # A new process recovers the incomplete event and handles it again.
        bus = EventBus(event_log=event_log)
        bus.subscribe("discovery", handler)
        recovered = await bus.recover()
        assert recovered == 1, f"the interrupted event must be re-queued, got {recovered}"
        bus.start()
        await bus.drain()
        bus.stop()

        # Nothing may have been duplicated by the replay.
        relationships_after = await storage.get_relationships("domain:example.com")
        assert len(relationships_after) == len(relationships_before), (
            f"replay duplicated a relationship: {len(relationships_before)} -> "
            f"{len(relationships_after)}"
        )

        node_after = await storage.get_node("ip:10.0.0.55")
        assert node_after.first_seen == node_before.first_seen, (
            "replay overwrote first_seen, so asset history no longer means anything"
        )

        assert await row_count(db_path, "SELECT COUNT(*) FROM evidence WHERE id = ?", event.id) == 1, (
            "evidence is keyed by event id; a replay must re-append it as a no-op"
        )
        assert await row_count(db_path, "SELECT COUNT(*) FROM nodes WHERE id = ?", "ip:10.0.0.55") == 1
        assert await row_count(db_path, "SELECT COUNT(*) FROM nodes WHERE id = ?", "domain:example.com") == 1
        assert await row_count(db_path, "SELECT COUNT(*) FROM relationships") == 1

        # In-run counters dedupe by id, so a replay must not inflate the summary
        # an operator reads at the end of a scan.
        assert stats.get("discoveries") == assets_before, (
            f"replay inflated the asset count: {assets_before} -> {stats.get('discoveries')}"
        )
        assert stats.get("relationships") == relationship_total_before, (
            f"replay inflated the relationship count: {relationship_total_before} -> "
            f"{stats.get('relationships')}"
        )

        # A third delivery must be equally safe.
        await handler(event)
        assert await row_count(db_path, "SELECT COUNT(*) FROM relationships") == 1
        assert await row_count(db_path, "SELECT COUNT(*) FROM evidence WHERE id = ?", event.id) == 1
        assert stats.get("discoveries") == assets_before

        print("idempotency test passed")
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


asyncio.run(main())
