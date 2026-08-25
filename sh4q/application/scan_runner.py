

import os
import time
from dataclasses import dataclass

from sh4q.config import Sh4qConfig, load_config
from sh4q.events import EventBus
from sh4q.events.event_log import DurableEventLog
from sh4q.handlers import make_discovery_handler
from sh4q.plugins.ct_plugin import CTPlugin
from sh4q.plugins.dns_plugin import DNSPlugin
from sh4q.plugins.http_plugin import HTTPPlugin
from sh4q.scheduler import Scheduler
from sh4q.scope import ScopeEngine
from sh4q.storage import SQLiteStorage
from sh4q.storage.evidence import SQLiteEvidenceStore


@dataclass
class ScanSummary:
    target: str
    scope_allowed: bool
    scope_reason: str
    discoveries: int
    relationships: int
    evidence: int
    recovered_events: int
    duration_seconds: float


def _default_config(target: str) -> Sh4qConfig:
    return Sh4qConfig(**{
        "scope": {"targets": [target], "ports": [80, 443]},
    })


async def run_scan(target: str, config_path: str | None = None) -> ScanSummary:
    start = time.monotonic()

    config = load_config(config_path) if config_path else _default_config(target)
    os.makedirs(config.output.directory, exist_ok=True)
    db_path = os.path.join(config.output.directory, "sh4q.db")

    scope = ScopeEngine(config)
    storage = SQLiteStorage(db_path)
    await storage.init()
    evidence_store = SQLiteEvidenceStore(db_path)
    await evidence_store.init()
    event_log = DurableEventLog(db_path)
    await event_log.init()

    bus = EventBus(event_log=event_log)

    discovery_count = 0
    stats: dict = {"relationships": 0}

    async def count_discoveries(event) -> None:
        nonlocal discovery_count
        discovery_count += 1


    bus.subscribe("discovery", make_discovery_handler(scope, storage, evidence_store, stats=stats))
    bus.subscribe("discovery", count_discoveries)
    recovered = await bus.recover()

    bus.start()

    scheduler = Scheduler(plugins=[DNSPlugin(), HTTPPlugin(scope), CTPlugin()], scope=scope, bus=bus)
    decision = await scheduler.run(target)

    await bus.drain()
    bus.stop()

    evidence_records = await evidence_store.list_for_target(target)

    return ScanSummary(
        target=target,
        scope_allowed=decision.allowed,
        scope_reason=decision.reason,
        discoveries=discovery_count,
        relationships=stats["relationships"],
        evidence=len(evidence_records),
        recovered_events=recovered,
        duration_seconds=time.monotonic() - start,
    )
