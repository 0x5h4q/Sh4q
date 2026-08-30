from __future__ import annotations

import json
from dataclasses import dataclass, field

from sh4q.storage.scan_runs import ScanRun
from sh4q.storage.db import open_sync_database


@dataclass(frozen=True)
class ScanReport:
    run: ScanRun
    asset_types: dict[str, int] = field(default_factory=dict)
    source_assets: dict[str, int] = field(default_factory=dict)
    relationships: int = 0
    evidence: int = 0
    dns_hostnames: int = 0
    dns_addresses: int = 0
    http_endpoints: int = 0
    http_hosts: int = 0
    technology_assets: int = 0
    technology_observations: int = 0
    dns_failures: dict[str, int] = field(default_factory=dict)
    http_failures: int = 0
    request_metrics: dict = field(default_factory=dict)
    stages: list[dict] = field(default_factory=list)


def build_scan_report(database: str, run: ScanRun) -> ScanReport:
    with open_sync_database(database) as db:
        asset_types = dict(db.execute(
            """SELECT n.type, COUNT(DISTINCT n.id)
            FROM scan_assets sa JOIN nodes n ON n.id = sa.asset_id
            WHERE sa.scan_run_id = ? GROUP BY n.type""",
            (run.id,),
        ).fetchall())
        source_assets = dict(db.execute(
            """SELECT source_plugin, COUNT(DISTINCT asset_id)
            FROM scan_assets WHERE scan_run_id = ? GROUP BY source_plugin""",
            (run.id,),
        ).fetchall())
        relationship_count = db.execute(
            "SELECT COUNT(DISTINCT relationship_id) FROM scan_assets WHERE scan_run_id = ?",
            (run.id,),
        ).fetchone()[0]
        evidence_count = db.execute(
            "SELECT COUNT(*) FROM evidence WHERE scan_run_id = ?", (run.id,)
        ).fetchone()[0]

        def relationship_counts(kind: str) -> tuple[int, int]:
            row = db.execute(
                """SELECT COUNT(DISTINCT r.from_id), COUNT(DISTINCT r.to_id)
                FROM scan_assets sa JOIN relationships r ON r.id = sa.relationship_id
                WHERE sa.scan_run_id = ? AND r.type = ?""",
                (run.id, kind),
            ).fetchone()
            return row[0], row[1]

        dns_hostnames, dns_addresses = relationship_counts("RESOLVES_TO")
        http_hosts, http_endpoints = relationship_counts("SERVES")
        _, technology_observations = relationship_counts("DETECTED_TECHNOLOGY")
        technology_relation_count = db.execute(
            """SELECT COUNT(*) FROM scan_assets sa
            JOIN relationships r ON r.id = sa.relationship_id
            WHERE sa.scan_run_id = ? AND r.type = 'DETECTED_TECHNOLOGY'""",
            (run.id,),
        ).fetchone()[0]

        dns_failures: dict[str, int] = {}
        http_failures = 0
        request_metrics = {}
        stages = []
        rows = db.execute(
            "SELECT kind, content FROM evidence WHERE scan_run_id = ?",
            (run.id,),
        ).fetchall()
        for kind, raw_content in rows:
            content = json.loads(raw_content)
            if kind == "discovered_dns_error":
                reason = content.get("reason") or (
                    "timeout" if "timed out" in content.get("error", "").lower() else "resolver_error"
                )
                dns_failures[reason] = dns_failures.get(reason, 0) + 1
            elif kind == "http_error":
                http_failures += 1
            elif kind == "request_metrics":
                request_metrics = content
            elif kind == "stage_metrics":
                stages = content.get("stages", [])

    return ScanReport(
        run=run,
        asset_types=asset_types,
        source_assets=source_assets,
        relationships=relationship_count,
        evidence=evidence_count,
        dns_hostnames=dns_hostnames,
        dns_addresses=dns_addresses,
        http_endpoints=http_endpoints,
        http_hosts=http_hosts,
        technology_assets=asset_types.get("technology", 0),
        technology_observations=technology_relation_count,
        dns_failures=dns_failures,
        http_failures=http_failures,
        request_metrics=request_metrics,
        stages=stages,
    )
