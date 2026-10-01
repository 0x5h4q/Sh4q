"""The graph is the authorized subset, ports included.

`docs/architecture_overview.md` labels the asset graph "the authorized
subset" and CLAUDE.md states it outright. `scope.ports` is part of that
authorization -- it decides which origins may be contacted -- but only
`_directory_observation` checked it before persisting. Six other handlers
authorized the hostname and ignored the port, so a URL on a port the
operator never authorized became inventory.

Live scans were shielded by plugin-side port checks. That is the same
reasoning that made `dns_resolution` look safe until durable recovery
handed it an event from another scan (test_cross_scope_recovery.py): "the
current emitter is careful" is true today and is not an invariant.

A denial must also be *visible*. Every other Gate 2 refusal prints a
gate_line; the one handler that already checked ports returned silently,
which would have made six more handlers drop observations without a word.
"""

import asyncio
import os
import tempfile

from sh4q.config import Sh4qConfig
from sh4q.events import Event
from sh4q.handlers import make_discovery_handler
from sh4q.scope import ScopeEngine
from sh4q.storage import SQLiteStorage
from sh4q.storage.evidence import SQLiteEvidenceStore

# Only 443 is authorized; 8443 never is.
BAD = 8443
GOOD = 443

# kind -> (payload on an unauthorized port, payload on an authorized port,
#          the url node each would create)
CASES = {
    "http_probe": (
        ({"final_url": f"https://example.com:{BAD}/", "status": 200}, f"url:https://example.com:{BAD}/"),
        ({"final_url": "https://example.com/", "status": 200}, "url:https://example.com/"),
        "http",
    ),
    "url_history_found": (
        ({"url": f"https://example.com:{BAD}/old", "domain": "example.com"}, f"url:https://example.com:{BAD}/old"),
        ({"url": "https://example.com/old", "domain": "example.com"}, "url:https://example.com/old"),
        "url-history",
    ),
    "javascript_endpoint_reference": (
        ({"value": f"https://example.com:{BAD}/api", "source_endpoint": "https://example.com/", "kind": "endpoint_reference"}, f"url:https://example.com:{BAD}/api"),
        ({"value": "https://example.com/api", "source_endpoint": "https://example.com/", "kind": "endpoint_reference"}, "url:https://example.com/api"),
        "javascript-extraction",
    ),
    "http_fingerprint": (
        ({"endpoint": f"https://example.com:{BAD}/", "technologies": ["nginx"]}, f"url:https://example.com:{BAD}/"),
        ({"endpoint": "https://example.com/", "technologies": ["nginx"]}, "url:https://example.com/"),
        "httpx-fingerprint",
    ),
    "vhost_observation": (
        ({"candidate": "example.com", "endpoint": f"https://example.com:{BAD}/", "status": 200, "classification": "candidate_observation"}, f"url:https://example.com:{BAD}/"),
        ({"candidate": "example.com", "endpoint": "https://example.com/", "status": 200, "classification": "candidate_observation"}, "url:https://example.com/"),
        "vhost-discovery",
    ),
    "directory_observation": (
        ({"url": f"https://example.com:{BAD}/admin", "status": 200, "path": "/admin", "classification": "candidate_observation"}, f"url:https://example.com:{BAD}/admin"),
        ({"url": "https://example.com/admin", "status": 200, "path": "/admin", "classification": "candidate_observation"}, "url:https://example.com/admin"),
        "directory-discovery",
    ),
}


def event_for(kind, data, plugin):
    return Event(type="discovery", payload={
        "kind": kind, "data": data, "source_plugin": plugin, "scan_target": "example.com",
    })


async def main() -> None:
    handle, db_path = tempfile.mkstemp(prefix="sh4q_port_policy_", suffix=".db")
    os.close(handle)
    os.remove(db_path)
    try:
        storage = SQLiteStorage(db_path)
        await storage.init()
        evidence = SQLiteEvidenceStore(db_path)
        await evidence.init()
        scope = ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"], "ports": [GOOD]}))
        assert not scope.authorize("example.com", BAD).allowed, "the premise of this test"
        assert scope.authorize("example.com", GOOD).allowed

        stats: dict = {}
        handler = make_discovery_handler(scope, storage, evidence, stats=stats)

        # --- an unauthorized port never becomes inventory -----------------
        for kind, ((bad_data, bad_node), _, plugin) in CASES.items():
            await handler(event_for(kind, bad_data, plugin))
            assert await storage.get_node(bad_node) is None, (
                f"{kind} persisted a URL on port {BAD}, which scope.ports does not authorize"
            )

        # --- and the authorized port still does ---------------------------
        for kind, (_, (good_data, good_node), plugin) in CASES.items():
            await handler(event_for(kind, good_data, plugin))
            assert await storage.get_node(good_node) is not None, (
                f"{kind} refused an authorized origin; the port check is too strict"
            )

        # --- an empty port list authorizes any port ------------------------
        # scope.ports = [] means every port is permitted (probing still
        # defaults to 80/443). The persistence check must honour that rather
        # than inventing a default.
        open_scope = ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"], "ports": []}))
        assert open_scope.authorize("example.com", BAD).allowed
        open_storage = SQLiteStorage(db_path + ".open")
        await open_storage.init()
        open_evidence = SQLiteEvidenceStore(db_path + ".open")
        await open_evidence.init()
        open_handler = make_discovery_handler(open_scope, open_storage, open_evidence, stats={})
        for kind, ((bad_data, bad_node), _, plugin) in CASES.items():
            await open_handler(event_for(kind, bad_data, plugin))
            assert await open_storage.get_node(bad_node) is not None, (
                f"{kind} refused port {BAD} under an empty port list, which authorizes every port"
            )

        # --- the batch path counts refusals instead of printing one each ---
        # url_history can carry thousands of URLs. Its host check already
        # counts rather than prints, and the summary surfaces the counter as
        # "Historical URLs rejected"; a port refusal joins the same count, so
        # the operator still sees that something was dropped.
        batch_stats: dict = {}
        batch_storage = SQLiteStorage(db_path + ".batch")
        await batch_storage.init()
        batch_evidence = SQLiteEvidenceStore(db_path + ".batch")
        await batch_evidence.init()
        batch_handler = make_discovery_handler(
            scope, batch_storage, batch_evidence, stats=batch_stats
        )
        await batch_handler(event_for("url_history_batch", {"urls": [
            "https://example.com/kept",
            f"https://example.com:{BAD}/dropped",
            f"http://example.com:{BAD}/dropped-too",
            "https://elsewhere.test/out-of-scope",
        ], "source": "waybackurls"}, "url-history"))
        assert await batch_storage.get_node("url:https://example.com/kept") is not None
        assert await batch_storage.get_node(f"url:https://example.com:{BAD}/dropped") is None
        assert await batch_storage.get_node(f"url:http://example.com:{BAD}/dropped-too") is None
        assert batch_stats.get("historical_urls_rejected") == 3, (
            "two port refusals and one host refusal must all be counted, got "
            f"{batch_stats.get('historical_urls_rejected')}"
        )
        assert batch_stats.get("historical_urls") == 1, batch_stats.get("historical_urls")

        # --- the directory edge anchors at the origin actually swept --------
        # The root node was a hardcoded `https://<target>/`, so a sweep of
        # http://host:8081/ wrote a root URL that had never been contacted and
        # that this very scope denies on port 443. A handler enforcing
        # "inventory is the authorized subset" cannot breach it one line later.
        lab = ScopeEngine(Sh4qConfig(scope={
            "targets": ["example.com"], "ports": [8081], "allow_private_addresses": True,
        }))
        assert not lab.authorize("example.com", 443).allowed, "the premise of this check"
        lab_storage = SQLiteStorage(db_path + ".lab")
        await lab_storage.init()
        lab_evidence = SQLiteEvidenceStore(db_path + ".lab")
        await lab_evidence.init()
        lab_handler = make_discovery_handler(lab, lab_storage, lab_evidence, stats={})
        await lab_handler(event_for("directory_observation", {
            "url": "http://example.com:8081/admin", "status": 200,
            "path": "/admin", "classification": "candidate_observation",
        }, "directory-discovery"))
        assert await lab_storage.get_node("url:http://example.com:8081/admin") is not None
        assert await lab_storage.get_node("url:http://example.com:8081/") is not None, (
            "the edge must anchor at the origin that was swept"
        )
        assert await lab_storage.get_node("url:https://example.com/") is None, (
            "a synthetic https root on an unauthorized port must not be written"
        )

        # --- a relative reference has no port, and must behave as before ----
        # `_effective_port` returns None for anything that is not an absolute
        # http(s) URL, which makes `authorize` skip the port rule. Relative
        # JavaScript references were refused before this change (no host) and
        # must still be refused for the same reason, not a new one.
        before = await storage.get_node("url:/api/v1/users")
        await handler(event_for("javascript_endpoint_reference", {
            "value": "/api/v1/users", "source_endpoint": "https://example.com/",
            "kind": "endpoint_reference",
        }, "javascript-extraction"))
        assert await storage.get_node("url:/api/v1/users") == before, (
            "a relative reference must be handled exactly as it was before"
        )

        print("persistence port policy test passed")
    finally:
        for path in (db_path, db_path + ".open", db_path + ".batch", db_path + ".lab"):
            if os.path.exists(path):
                os.remove(path)


asyncio.run(main())
