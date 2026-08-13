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
    db_path = "/tmp/sh4q_week4_test.db"
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

    print("=== TEST 1: evidence preserved even when Gate 2 denies the asset ===")
    bus = EventBus(event_log=event_log)
    bus.subscribe("discovery", make_discovery_handler(scope, storage, evidence_store))
    bus.start()

    denied_event = Event(type="discovery", payload={
        "kind": "dns_resolution",
        "data": {"domain": "example.com", "ip": "93.184.216.34"},
        "source_plugin": "dns",
    })
    await bus.publish(denied_event)
    await bus.drain()
    bus.stop()

    ip_node = await storage.get_node("ip:93.184.216.34")
    ev = await evidence_store.get(denied_event.id)
    print(f"  asset persisted (should be False): {ip_node is not None}")
    print(f"  evidence preserved (should be True): {ev is not None}")


asyncio.run(main())