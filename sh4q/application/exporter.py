from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path

from sh4q.storage.scan_runs import ScanRun


class ScanOwnershipUnavailableError(Exception):
    pass


def export_scan(
    database: str,
    run: ScanRun,
    *,
    format: str,
    output: Path,
    force: bool = False,
) -> int:
    with sqlite3.connect(database) as db:
        rows = db.execute(
            """SELECT n.type, n.value, n.attributes,
            group_concat(DISTINCT sa.source_plugin)
            FROM scan_assets sa JOIN nodes n ON n.id = sa.asset_id
            WHERE sa.scan_run_id = ?
            GROUP BY n.id, n.type, n.value, n.attributes
            ORDER BY n.type, n.value""",
            (run.id,),
        ).fetchall()
        evidence_count = db.execute(
            "SELECT COUNT(*) FROM evidence WHERE scan_run_id = ?", (run.id,)
        ).fetchone()[0]
    if not rows and evidence_count:
        raise ScanOwnershipUnavailableError(
            f"scan {run.id} contains {evidence_count} evidence record(s) but no "
            "scan-owned assets; it predates the asset-ownership migration"
        )
    if output.exists() and not force:
        raise FileExistsError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    assets = [
        {
            "type": row[0],
            "value": row[1],
            "attributes": json.loads(row[2]),
            "sources": sorted((row[3] or "").split(",")),
        }
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
            writer = csv.DictWriter(
                stream,
                fieldnames=["scan_id", "target", "type", "value", "sources", "attributes"],
            )
            writer.writeheader()
            for item in assets:
                writer.writerow(
                    {
                        "scan_id": run.id,
                        "target": run.target,
                        "type": item["type"],
                        "value": item["value"],
                        "sources": ",".join(item["sources"]),
                        "attributes": json.dumps(item["attributes"], sort_keys=True),
                    }
                )
    else:
        raise ValueError(f"unsupported export format: {format}")
    return len(assets)
