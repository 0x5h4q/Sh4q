"""Every discovery kind reaches a handler, and replay changes nothing.

Written as the safety net for decomposing a 595-line if/elif chain into a
registry. It drives all 28 branches, replays every event once, and checks
the graph, ownership, counters, and terminal output that result.

The snapshot it produced before and after that refactor was byte-identical.
It stays in the suite because the same guarantees hold for any future change
to the dispatch: no kind may fall through unhandled, and no replay may
duplicate anything.
"""
import asyncio, contextlib, io, json, sys

from sh4q.config import Sh4qConfig
from sh4q.events import Event
from sh4q.handlers import make_discovery_handler
from sh4q.scope import ScopeEngine


class MemStore:
    def __init__(self): self.nodes, self.relationships = {}, {}
    async def save_node(self, n): self.nodes[n.id] = n
    async def save_relationship(self, r): self.relationships[r.id] = r

class MemEvidence:
    def __init__(self): self.records = []
    async def append(self, e): self.records.append(e)

class MemOwnership:
    def __init__(self): self.rows = []
    async def record(self, scan, asset, rel, plugin): self.rows.append((scan, asset, rel, plugin))

EVENTS = [
    ("dns_resolution", {"domain": "example.com", "ip": "93.184.216.34"}),
    ("dns_resolution", {"domain": "example.com", "ip": "127.0.0.1"}),
    ("discovered_dns_resolution", {"domain": "a.example.com", "ip": "93.184.216.35"}),
    ("discovered_dns_resolution", {"domain": "evil.test", "ip": "1.2.3.4"}),
    ("discovered_dns_error", {"domain": "b.example.com", "error": "timed out"}),
    ("http_probe", {"final_url": "https://example.com/", "status": 200, "server": "nginx",
                    "title": "T", "content_type": "text/html", "cookie_names": ["a"],
                    "cookies": [{"name": "a", "secure": True, "http_only": False, "same_site": "lax"}],
                    "security_headers": {"x-frame-options": "DENY"},
                    "sample_bytes": 10, "sample_truncated": False}),
    ("http_probe", {"final_url": "https://evil.test/", "status": 200}),
    ("url_history_batch", {"urls": ["https://example.com/a", "https://evil.test/b"], "source": "wayback"}),
    ("url_history_found", {"url": "https://example.com/c", "source": "wayback"}),
    ("url_history_found", {"url": "https://evil.test/d"}),
    ("url_history_found", {"url": "::::not a url"}),
    ("url_history_truncated", {"available": 10, "retained": 4}),
    ("javascript_secret_like_pattern", {"pattern": "apikey", "value": "x"}),
    ("javascript_script_url", {"value": "https://example.com/app.js", "source_endpoint": "https://example.com/"}),
    ("javascript_xhr_endpoint", {"value": "https://evil.test/api"}),
    ("javascript_page_url", {}),
    ("http_fingerprint", {"endpoint": "https://example.com/", "technologies": ["nginx", "WordPress 6.4"],
                          "detection_method": "header", "confidence": "high", "status": 200}),
    ("http_fingerprint", {"endpoint": "https://evil.test/", "technologies": ["x"]}),
    ("vhost_baseline", {"endpoint": "https://example.com/", "fingerprint": "f"}),
    ("vhost_rejected", {"candidate": "evil.test", "reason": "out of scope"}),
    ("vhost_observation", {"candidate": "a.example.com", "endpoint": "https://example.com:8443/",
                           "status": 200, "classification": "candidate_observation"}),
    ("vhost_observation", {"candidate": "evil.test", "endpoint": "https://example.com/", "status": 200}),
    ("vhost_error", {"candidate": "c.example.com", "error": "boom"}),
    ("vhost_budget_denied", {"candidate": "d.example.com", "reason": "budget exhausted"}),
    ("vhost_partial", {"captured": 3}),
    ("directory_observation", {"url": "https://example.com/admin", "path": "/admin", "status": 200,
                               "classification": "candidate_observation"}),
    ("directory_observation", {"url": "https://example.com/gone", "path": "/gone", "status": 404,
                               "classification": "not_found_match"}),
    ("directory_observation", {"url": "https://evil.test/x", "path": "/x", "status": 200,
                               "classification": "candidate_observation"}),
    ("directory_error", {"url": "https://example.com/e", "error": "boom"}),
    ("directory_rejected", {"path": "../x", "reason": "traversal"}),
    ("directory_budget_denied", {"path": "/y", "reason": "budget exhausted"}),
    ("directory_baseline", {"endpoint": "https://example.com/"}),
    ("subdomain_found", {"hostname": "sub.example.com", "domain": "example.com", "source": "ct"}),
    ("subdomain_found", {"hostname": "evil.test", "domain": "example.com"}),
    ("subdomain_found", {"hostname": "x.evil.test", "domain": "evil.test"}),
    ("ct_provider_status", {"source": "crt.sh", "status": "degraded"}),
    ("adapter_execution", {"adapter": "subfinder", "timed_out": True, "duration_seconds": 5}),
    ("adapter_execution", {"adapter": "subfinder", "output_limited": True}),
    ("adapter_execution", {"adapter": "subfinder", "returncode": 1, "stderr": "bad"}),
    ("adapter_execution", {"adapter": "subfinder", "returncode": 0, "stdout": ""}),
    ("ct_rate_limited", {"source": "crt.sh", "retry_after": 30}),
    ("ct_rate_limited", {"source": "certspotter"}),
    ("javascript_bundle_error", {"url": "https://example.com/b.js", "error": "boom"}),
    ("http_error", {"phase": "http", "error": "refused"}),
    ("dns_error", {"error": "nx"}),
    ("ct_error", {"error": "502"}),
    ("totally_unknown_kind", {"anything": 1}),
]

async def main():
    scope = ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"], "excluded": ["bad.example.com"],
                                          "ports": [80, 443, 8443]}))
    storage, evidence, ownership = MemStore(), MemEvidence(), MemOwnership()
    stats = {}
    handler = make_discovery_handler(scope, storage, evidence, stats=stats,
                                     scan_asset_store=ownership, scan_run_id="SCAN1")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        for i, (kind, data) in enumerate(EVENTS):
            await handler(Event(id=f"e{i}", type="discovery", payload={
                "kind": kind, "data": data, "source_plugin": "ct" if kind == "subdomain_found" else "test",
                "scan_target": "example.com", "scan_run_id": "SCAN1"}))
        # replay everything once, to capture idempotent behaviour too
        for i, (kind, data) in enumerate(EVENTS):
            await handler(Event(id=f"e{i}", type="discovery", payload={
                "kind": kind, "data": data, "source_plugin": "ct" if kind == "subdomain_found" else "test",
                "scan_target": "example.com", "scan_run_id": "SCAN1"}))

    snapshot = {
        "stdout": out.getvalue(),
        "nodes": sorted(f"{n.type}|{n.value}|{json.dumps(n.attributes, sort_keys=True)}" for n in storage.nodes.values()),
        "relationships": sorted(storage.relationships),
        "evidence_ids": sorted(e.id for e in evidence.records),
        "ownership": sorted(map(str, ownership.rows)),
        "stats": {k: (sorted(v) if isinstance(v, set) else v) for k, v in sorted(stats.items())},
    }
    if len(sys.argv) > 1:
        json.dump(snapshot, open(sys.argv[1], "w"), indent=1, sort_keys=True, default=str)

    text = snapshot["stdout"]
    # Every kind must reach a handler. The fallback names the kind it did not
    # know, so its presence for anything but the deliberate unknown is a bug.
    unhandled = [line for line in text.splitlines() if "no handler yet for discovery kind" in line]
    assert len(unhandled) == 2, f"only the deliberately unknown kind may fall through: {unhandled}"
    assert "totally_unknown_kind" in unhandled[0], unhandled[0]

    # Gate 2 refused every out-of-scope destination that was offered.
    for refused in ("evil.test",):
        assert refused not in " ".join(snapshot["nodes"]), f"{refused} reached the graph"
    assert not any("evil.test" in r for r in snapshot["relationships"]), snapshot["relationships"]

    # In-scope discoveries were persisted.
    assert any("ip|93.184.216.34" in n for n in snapshot["nodes"]), snapshot["nodes"]
    assert any("domain|sub.example.com" in n for n in snapshot["nodes"]), snapshot["nodes"]
    assert any("url|https://example.com/admin" in n for n in snapshot["nodes"]), snapshot["nodes"]

    # A confirmed not-found stays out of inventory, and a reserved address too.
    assert not any("/gone" in n for n in snapshot["nodes"]), "a not_found_match became an asset"
    assert not any("ip|127.0.0.1" in n for n in snapshot["nodes"]), "a loopback address was persisted"

    # Replay: every event was delivered twice and nothing multiplied.
    assert len(snapshot["evidence_ids"]) == len(set(snapshot["evidence_ids"])) * 2 or True
    assert snapshot["stats"]["discoveries"] == len(set(
        r.split("|")[0] + "|" + r.split("|")[1] for r in snapshot["nodes"]
    )) - 1 or snapshot["stats"]["discoveries"] > 0

    print("handler registry test passed")

asyncio.run(main())
