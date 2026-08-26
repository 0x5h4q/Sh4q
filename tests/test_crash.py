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
    db_path = "/tmp/sh4q_crash_test.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    cfg = Sh4qConfig(**{"scope": {"targets": ["example.com", "10.0.0.0/24"], "allow_private_addresses": True}})
    scope = ScopeEngine(cfg)
    storage = SQLiteStorage(db_path)
    await storage.init()
    evidence_store = SQLiteEvidenceStore(db_path)
    await evidence_store.init()
    event_log = DurableEventLog(db_path)
    await event_log.init()

    print("=== SIMULATING A CRASH ===")
    crash_event = Event(type="discovery", payload={
        "kind": "dns_resolution",
        "data": {"domain": "example.com", "ip": "10.0.0.99"},
        "source_plugin": "dns",
    })
    await event_log.record_pending(crash_event)

    stuck_event = Event(type="discovery", payload={
        "kind": "dns_resolution",
        "data": {"domain": "example.com", "ip": "10.0.0.100"},
        "source_plugin": "dns",
    })
    await event_log.record_pending(stuck_event)
    await event_log.mark_processing(stuck_event.id)
    print("  two events left unfinished in the durable log")

    print()
    print("=== NEW PROCESS STARTS ===")
    new_bus = EventBus(event_log=event_log)
    new_bus.subscribe("discovery", make_discovery_handler(scope, storage, evidence_store))
    recovered_count = await new_bus.recover()
    print(f"  recovered {recovered_count} unfinished events")

    new_bus.start()
    await new_bus.drain()
    new_bus.stop()

    node1 = await storage.get_node("ip:10.0.0.99")
    node2 = await storage.get_node("ip:10.0.0.100")
    print(f"  PENDING event recovered: {node1 is not None}")
    print(f"  PROCESSING event recovered: {node2 is not None}")


asyncio.run(main())
