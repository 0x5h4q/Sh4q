from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4
from sh4q.storage.db import open_sync_database


@dataclass(frozen=True)
class ScanRun:
    id: str
    target: str
    started_at: str
    completed_at: str | None
    status: str
    config_hash: str | None = None
    template_name: str | None = None
    stages: str | None = None
    tool_versions: str | None = None


def _scan_run_from_row(row) -> ScanRun | None:
    """Build a ScanRun from a database row, tolerating narrow rows."""
    if row is None:
        return None
    return ScanRun(
        id=row[0],
        target=row[1],
        started_at=row[2],
        completed_at=row[3],
        status=row[4],
        config_hash=row[5] if len(row) > 5 else None,
        template_name=row[6] if len(row) > 6 else None,
        stages=row[7] if len(row) > 7 else None,
        tool_versions=row[8] if len(row) > 8 else None,
    )


def scan_asset_count(database: str, scan_id: str) -> int:
    with open_sync_database(database, "count scan assets") as db:
        table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='scan_assets'"
        ).fetchone()
        if table is None:
            return 0
        return db.execute(
            "SELECT COUNT(DISTINCT asset_id) FROM scan_assets WHERE scan_run_id = ?",
            (scan_id,),
        ).fetchone()[0]


def create_scan(
    database: str,
    target: str,
    *,
    config_hash: str | None = None,
    template_name: str | None = None,
    stages: str | None = None,
) -> ScanRun:
    started = datetime.now(timezone.utc).isoformat()
    run = ScanRun(
        id=uuid4().hex,
        target=target,
        started_at=started,
        completed_at=None,
        status="RUNNING",
        config_hash=config_hash,
        template_name=template_name,
        stages=stages,
    )
    with open_sync_database(database, "create scan run") as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS scan_runs ("
            "id TEXT PRIMARY KEY, "
            "target TEXT NOT NULL, "
            "started_at TEXT NOT NULL, "
            "completed_at TEXT, "
            "status TEXT NOT NULL, "
            "config_hash TEXT, "
            "template_name TEXT, "
            "stages TEXT, "
            "tool_versions TEXT)"
        )
        db.execute(
            "INSERT INTO scan_runs (id, target, started_at, completed_at, status, config_hash, template_name, stages, tool_versions) "
            "VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?)",
            (
                run.id,
                run.target,
                run.started_at,
                run.status,
                run.config_hash,
                run.template_name,
                run.stages,
                None,
            ),
        )
        db.commit()
    return run


def finish_scan(
    database: str,
    scan_id: str,
    status: str,
    *,
    tool_versions: str | None = None,
) -> None:
    with open_sync_database(database, "finish scan run") as db:
        if tool_versions is not None:
            db.execute(
                "UPDATE scan_runs SET completed_at = ?, status = ?, tool_versions = ? WHERE id = ?",
                (
                    datetime.now(timezone.utc).isoformat(),
                    status,
                    tool_versions,
                    scan_id,
                ),
            )
        else:
            db.execute(
                "UPDATE scan_runs SET completed_at = ?, status = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), status, scan_id),
            )
        db.commit()


_SCAN_RUNS_TABLE = (
    "CREATE TABLE IF NOT EXISTS scan_runs ("
    "id TEXT PRIMARY KEY, "
    "target TEXT NOT NULL, "
    "started_at TEXT NOT NULL, "
    "completed_at TEXT, "
    "status TEXT NOT NULL, "
    "config_hash TEXT, "
    "template_name TEXT, "
    "stages TEXT, "
    "tool_versions TEXT)"
)

_SCAN_RUN_COLUMNS = (
    "id, target, started_at, completed_at, status, "
    "config_hash, template_name, stages, tool_versions"
)


def list_scans(database: str, limit: int | None = 50) -> list[ScanRun]:
    """Recorded scan runs, newest first. `limit=None` returns every one.

    A requested limit is honoured as asked; this clamped to 500 silently.
    """
    with open_sync_database(database, "list scan runs") as db:
        db.execute(_SCAN_RUNS_TABLE)
        query = (
            f"SELECT {_SCAN_RUN_COLUMNS} FROM scan_runs ORDER BY started_at DESC"
        )
        if limit is None:
            rows = db.execute(query).fetchall()
        else:
            rows = db.execute(query + " LIMIT ?", (max(1, limit),)).fetchall()
    return [_scan_run_from_row(row) for row in rows]


def count_scans(database: str) -> int:
    """How many scan runs are recorded, whatever a listing chose to show."""
    with open_sync_database(database, "count scan runs") as db:
        db.execute(_SCAN_RUNS_TABLE)
        return int(db.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0])


def latest_scan(
    database: str, target: str | None = None, *, completed_only: bool = True
) -> ScanRun | None:
    query = f"SELECT {_SCAN_RUN_COLUMNS} FROM scan_runs"
    params = []
    conditions = []
    if completed_only:
        conditions.append("status = 'COMPLETED'")
    if target:
        conditions.append("target = ?")
        params.append(target)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY started_at DESC LIMIT 1"
    with open_sync_database(database, "read latest scan") as db:
        row = db.execute(query, params).fetchone()
    return _scan_run_from_row(row)


def get_scan(database: str, scan_id: str) -> ScanRun | None:
    with open_sync_database(database, "read scan") as db:
        row = db.execute(
            f"SELECT {_SCAN_RUN_COLUMNS} FROM scan_runs WHERE id = ?",
            (scan_id,),
        ).fetchone()
    return _scan_run_from_row(row)
