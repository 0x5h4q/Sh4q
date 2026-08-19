import asyncio
import os

from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine
from sh4q.storage import SQLiteStorage
from sh4q.storage.evidence import SQLiteEvidenceStore
from sh4q.events import EventBus
from sh4q.scheduler import Scheduler
from sh4q.handlers import make_discovery_handler
from sh4q.plugins.dns_plugin import DNSPlugin


async def main():
    db_path = "/tmp/sh4q_real_dns_test.db"

    if os.path.exists(db_path):
        os.remove(db_path)

    cfg = Sh4qConfig(
        **{
            "scope": {
                "targets": [
                    "example.com",
                    "0.0.0.0/0",
                ]
            }
        }
    )

    scope = ScopeEngine(cfg)

    storage = SQLiteStorage(db_path)
    await storage.init()

    evidence_store = SQLiteEvidenceStore(db_path)
    await evidence_store.init()

    bus = EventBus()

    bus.subscribe(
        "discovery",
        make_discovery_handler(
            scope,
            storage,
            evidence_store,
        ),
    )

    bus.start()

    scheduler = Scheduler(
        plugins=[DNSPlugin()],
        scope=scope,
        bus=bus,
    )

    await scheduler.run("example.com")
    await bus.drain()
    bus.stop()

    print()

    domain_node = await storage.get_node("domain:example.com")
    rels = await storage.get_relationships("domain:example.com")

    print(f"domain node saved: {domain_node is not None}")
    print(
        f"resolved relationships: "
        f"{[(r.from_id, r.type, r.to_id) for r in rels]}"
    )


asyncio.run(main())