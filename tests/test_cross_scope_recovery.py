"""A recovered event is authorized under the scope that handles it.

Event delivery is at-least-once and durable: `recover_unfinished` selects
every PENDING/PROCESSING/FAILED row in the database with no filter on
target or scan run (event_log.py), and `run_scan` recovers before Gate 1
authorizes the new target. One database can therefore hand a later scan an
unfinished event produced by a scan of a completely different target.

`_dns_resolution` assumed otherwise. It saved its domain node
unconditionally and checked only the resolved address, on the reasoning
that "the hostname was authorized at Gate 1" -- true only while the event
belongs to the scan currently running. A recovered event for an
out-of-scope host wrote the domain, its address, and the RESOLVES_TO edge
into the new scan's graph.

This is the same shape as the `subdomain_found` Gate 2 bypass fixed in
v1.3.0: save before authorize. Its regression lives in
test_scope_engine.py; this file covers the recovery route that no
same-scope replay test could reach.
"""

import asyncio
import os
import tempfile

from sh4q.config import Sh4qConfig
from sh4q.events import Event, EventBus
from sh4q.events.event_log import DurableEventLog
from sh4q.handlers import make_discovery_handler
from sh4q.scope import ScopeEngine
from sh4q.storage import SQLiteStorage
from sh4q.storage.evidence import SQLiteEvidenceStore

OUTSIDER = "evil.com"
ADDRESS = "93.184.216.34"


def scope_for(*targets: str) -> ScopeEngine:
    return ScopeEngine(Sh4qConfig(scope={"targets": list(targets)}))


async def main() -> None:
    handle, db_path = tempfile.mkstemp(prefix="sh4q_cross_scope_", suffix=".db")
    os.close(handle)
    os.remove(db_path)
    try:
        storage = SQLiteStorage(db_path)
        await storage.init()
        evidence = SQLiteEvidenceStore(db_path)
        await evidence.init()
        event_log = DurableEventLog(db_path)
        await event_log.init()

        # --- scan A: target evil.com, interrupted mid-handling ------------
        interrupted = Event(type="discovery", payload={
            "kind": "dns_resolution",
            "data": {"domain": OUTSIDER, "ip": ADDRESS},
            "source_plugin": "dns",
            "scan_target": OUTSIDER,
        })
        await event_log.record_pending(interrupted)
        await event_log.mark_processing(interrupted.id)

        # --- scan B: a scope that does not authorize evil.com -------------
        scope = scope_for("example.com")
        assert not scope.authorize(OUTSIDER).allowed, "the premise of this test"

        stats: dict = {}
        handler = make_discovery_handler(scope, storage, evidence, stats=stats)
        bus = EventBus(event_log=event_log)
        bus.subscribe("discovery", handler)
        recovered = await bus.recover()
        assert recovered == 1, f"the interrupted event must be re-queued, got {recovered}"
        bus.start()
        await bus.drain()
        bus.stop()

        # Nothing out of scope may have entered scan B's graph.
        assert await storage.get_node(f"domain:{OUTSIDER}") is None, (
            "a recovered event was authorized under the scope that produced it, "
            "not the scope handling it"
        )
        assert await storage.get_node(f"ip:{ADDRESS}") is None, (
            "the address of an unauthorized host must not be persisted either"
        )
        assert await storage.get_relationships(f"domain:{OUTSIDER}") == [], (
            "no RESOLVES_TO edge may be written for an unauthorized host"
        )

        # Evidence is the audit trail and keeps the observation regardless.
        # A Gate 2 denial is a recorded outcome, not an error.
        assert await evidence.get(interrupted.id) is not None, (
            "the denied observation must still be auditable"
        )

        # The same scope must still accept its own in-scope resolution, or the
        # fix would have closed the gate on everything.
        allowed = Event(type="discovery", payload={
            "kind": "dns_resolution",
            "data": {"domain": "example.com", "ip": ADDRESS},
            "source_plugin": "dns",
            "scan_target": "example.com",
        })
        await handler(allowed)
        assert await storage.get_node("domain:example.com") is not None
        assert await storage.get_node(f"ip:{ADDRESS}") is not None
        assert len(await storage.get_relationships("domain:example.com")) == 1

        # A subdomain of the authorized target inherits, as everywhere else.
        inherited = Event(type="discovery", payload={
            "kind": "dns_resolution",
            "data": {"domain": "api.example.com", "ip": ADDRESS},
            "source_plugin": "dns",
            "scan_target": "example.com",
        })
        await handler(inherited)
        assert await storage.get_node("domain:api.example.com") is not None, (
            "subdomain inheritance must still apply at this handler"
        )

        # The address-safety policy is a separate check and still runs: an
        # authorized hostname resolving to a reserved address is refused.
        private = Event(type="discovery", payload={
            "kind": "dns_resolution",
            "data": {"domain": "internal.example.com", "ip": "127.0.0.1"},
            "source_plugin": "dns",
            "scan_target": "example.com",
        })
        await handler(private)
        assert await storage.get_node("ip:127.0.0.1") is None, (
            "authorize_resolved_address must still reject a reserved address"
        )

        print("cross-scope recovery test passed")
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


asyncio.run(main())
