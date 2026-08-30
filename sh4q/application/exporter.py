from __future__ import annotations

import csv
import json
from pathlib import Path

from sh4q.storage.scan_runs import ScanRun
from sh4q.application.results import list_technology_observations
from sh4q.storage.db import open_sync_database


class ScanOwnershipUnavailableError(Exception):
    pass


def _http_inventory(db, scan_id: str) -> list[dict]:
    endpoint_rows = db.execute(
        """SELECT DISTINCT domain.id, domain.value, endpoint.id, endpoint.value,
        endpoint.attributes
        FROM scan_assets sa
        JOIN relationships serves ON serves.id = sa.relationship_id
        JOIN nodes domain ON domain.id = serves.from_id
        JOIN nodes endpoint ON endpoint.id = serves.to_id
        WHERE sa.scan_run_id = ? AND serves.type = 'SERVES'
          AND domain.type = 'domain' AND endpoint.type = 'url'
        ORDER BY endpoint.value""",
        (scan_id,),
    ).fetchall()
    inventory = []
    for domain_id, domain, endpoint_id, endpoint, raw_endpoint_attributes in endpoint_rows:
        address_rows = db.execute(
            """SELECT DISTINCT address.value
            FROM scan_assets sa
            JOIN relationships resolves ON resolves.id = sa.relationship_id
            JOIN nodes address ON address.id = resolves.to_id
            WHERE sa.scan_run_id = ? AND resolves.type = 'RESOLVES_TO'
              AND resolves.from_id = ? AND address.type = 'ip'
            ORDER BY address.value""",
            (scan_id, domain_id),
        ).fetchall()
        technology_rows = db.execute(
            """SELECT technology.value, detection.attributes, sa.source_plugin
            FROM scan_assets sa
            JOIN relationships detection ON detection.id = sa.relationship_id
            JOIN nodes technology ON technology.id = detection.to_id
            WHERE sa.scan_run_id = ? AND detection.type = 'DETECTED_TECHNOLOGY'
              AND detection.from_id = ? AND technology.type = 'technology'
            ORDER BY technology.value""",
            (scan_id, endpoint_id),
        ).fetchall()
        source_rows = db.execute(
            """SELECT DISTINCT sa.source_plugin
            FROM scan_assets sa JOIN relationships r ON r.id = sa.relationship_id
            WHERE sa.scan_run_id = ? AND (r.to_id = ? OR r.from_id = ?)
            ORDER BY sa.source_plugin""",
            (scan_id, endpoint_id, endpoint_id),
        ).fetchall()
        technologies = []
        sources = {row[0] for row in source_rows if row[0]}
        for technology, raw_attributes, source in technology_rows:
            attributes = json.loads(raw_attributes)
            technologies.append({
                "name": technology,
                "category": attributes.get("category", ""),
                "version": attributes.get("version", ""),
                "confidence": attributes.get("confidence", ""),
                "signal": attributes.get("raw_observation", ""),
                "source": source,
            })
            if source:
                sources.add(source)
        endpoint_attributes = json.loads(raw_endpoint_attributes)
        inventory.append({
            "type": "http-inventory",
            "domain": domain,
            "endpoint": endpoint,
            "http_status": endpoint_attributes.get("status"),
            "resolved_addresses": [row[0] for row in address_rows],
            "technologies": technologies,
            "sources": sorted(sources),
        })
    return inventory


def export_scan(
    database: str,
    run: ScanRun,
    *,
    format: str,
    output: Path,
    force: bool = False,
    alive: str | None = None,
    asset_type: str | None = None,
) -> int:
    if alive not in (None, "http", "dns"):
        raise ValueError(f"unsupported alive filter: {alive}")
    if alive and asset_type:
        raise ValueError("--alive and --type cannot be combined")
    with open_sync_database(database) as db:
        inventory_assets = _http_inventory(db, run.id) if asset_type == "http-inventory" else None
        if alive in ("http", "dns"):
            relationship_type = "SERVES" if alive == "http" else "RESOLVES_TO"
            endpoint_type = "url" if alive == "http" else "ip"
            rows = db.execute(
                """SELECT domain.type, domain.value, domain.attributes,
                group_concat(DISTINCT sa.source_plugin), endpoint.value, endpoint.attributes
                FROM scan_assets sa
                JOIN relationships r ON r.id = sa.relationship_id
                JOIN nodes domain ON domain.id = r.from_id
                JOIN nodes endpoint ON endpoint.id = r.to_id
                WHERE sa.scan_run_id = ? AND r.type = ?
                  AND domain.type = 'domain' AND endpoint.type = ?
                GROUP BY domain.id, domain.type, domain.value, domain.attributes,
                  endpoint.id, endpoint.value, endpoint.attributes
                ORDER BY domain.value, endpoint.value""",
                (run.id, relationship_type, endpoint_type),
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT n.type, n.value, n.attributes,
                group_concat(DISTINCT sa.source_plugin)
                FROM scan_assets sa JOIN nodes n ON n.id = sa.asset_id
                WHERE sa.scan_run_id = ?
                GROUP BY n.id, n.type, n.value, n.attributes
                ORDER BY n.type, n.value""",
                (run.id,),
            ).fetchall()
        owned_asset_count = db.execute(
            "SELECT COUNT(*) FROM scan_assets WHERE scan_run_id = ?", (run.id,)
        ).fetchone()[0]
        evidence_count = db.execute(
            "SELECT COUNT(*) FROM evidence WHERE scan_run_id = ?", (run.id,)
        ).fetchone()[0]
    if not owned_asset_count and evidence_count:
        raise ScanOwnershipUnavailableError(
            f"scan {run.id} contains {evidence_count} evidence record(s) but no "
            "scan-owned assets; it predates the asset-ownership migration"
        )
    if output.exists() and not force:
        raise FileExistsError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    if asset_type == "http-inventory":
        assets = inventory_assets or []
    elif asset_type == "technology":
        observations = list_technology_observations(database, scan_id=run.id, limit=1000)
        assets = [
            {
                "type": "technology",
                "value": item.technology,
                "endpoint": item.endpoint,
                "category": item.category,
                "version": item.version,
                "confidence": item.confidence,
                "http_status": item.status,
                "signal": item.signal,
            }
            for item in observations
        ]
    else:
        assets = [
        {
            "type": row[0],
            "value": row[1],
            "attributes": json.loads(row[2]),
            "sources": sorted((row[3] or "").split(",")),
        }
        | ({"endpoint": row[4], "endpoint_attributes": json.loads(row[5])} if alive in ("http", "dns") else {})
        for row in rows
        ]

    if format == "json":
        document = {
            "scan": {
                "id": run.id,
                "target": run.target,
                "started_at": run.started_at,
                "completed_at": run.completed_at,
                "status": run.status,
            },
            "asset_count": len(assets),
            "assets": assets,
        }
        output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    elif format == "csv":
        with output.open("w", newline="", encoding="utf-8") as stream:
            if asset_type == "technology":
                fieldnames = [
                    "scan_id", "target", "endpoint", "technology", "category",
                    "version", "confidence", "http_status", "signal",
                ]
            elif asset_type == "http-inventory":
                fieldnames = [
                    "scan_id", "target", "domain", "endpoint", "http_status",
                    "resolved_addresses", "technologies", "technology_categories",
                    "technology_versions", "technology_confidences",
                    "technology_signals", "sources",
                ]
            else:
                fieldnames = ["scan_id", "target", "type", "value", "sources", "attributes"]
                if alive == "http":
                    fieldnames.extend(["endpoint", "http_status"])
                elif alive == "dns":
                    fieldnames.append("resolved_address")
            writer = csv.DictWriter(
                stream,
                fieldnames=fieldnames,
            )
            writer.writeheader()
            for item in assets:
                if asset_type == "technology":
                    writer.writerow({
                        "scan_id": run.id,
                        "target": run.target,
                        "endpoint": item["endpoint"],
                        "technology": item["value"],
                        "category": item["category"],
                        "version": item["version"],
                        "confidence": item["confidence"],
                        "http_status": item["http_status"],
                        "signal": item["signal"],
                    })
                elif asset_type == "http-inventory":
                    observations = item["technologies"]
                    writer.writerow({
                        "scan_id": run.id,
                        "target": run.target,
                        "domain": item["domain"],
                        "endpoint": item["endpoint"],
                        "http_status": item["http_status"],
                        "resolved_addresses": ";".join(item["resolved_addresses"]),
                        "technologies": ";".join(value["name"] for value in observations),
                        "technology_categories": ";".join(value["category"] for value in observations),
                        "technology_versions": ";".join(value["version"] for value in observations),
                        "technology_confidences": ";".join(value["confidence"] for value in observations),
                        "technology_signals": ";".join(value["signal"] for value in observations),
                        "sources": ";".join(item["sources"]),
                    })
                else:
                    writer.writerow({
                        "scan_id": run.id,
                        "target": run.target,
                        "type": item["type"],
                        "value": item["value"],
                        "sources": ",".join(item["sources"]),
                        "attributes": json.dumps(item["attributes"], sort_keys=True),
                        **({"endpoint": item["endpoint"], "http_status": item["endpoint_attributes"].get("status")} if alive == "http" else {"resolved_address": item["endpoint"]} if alive == "dns" else {}),
                    })
    else:
        raise ValueError(f"unsupported export format: {format}")
    return len(assets)
