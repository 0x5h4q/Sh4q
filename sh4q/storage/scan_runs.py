from __future__ import annotations

from dataclasses import dataclass
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


def scan_asset_count(database: str, scan_id: str) -> int:
    with open_sync_database(database) as db:
        table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='scan_assets'"
        ).fetchone()
        if table is None:
            return 0
        return db.execute(
            "SELECT COUNT(DISTINCT asset_id) FROM scan_assets WHERE scan_run_id = ?",
            (scan_id,),
        ).fetchone()[0]


def create_scan(database: str, target: str) -> ScanRun:
    started = datetime.now(timezone.utc).isoformat()
    run = ScanRun(uuid4().hex, target, started, None, "RUNNING")
    with open_sync_database(database) as db:
        db.execute("CREATE TABLE IF NOT EXISTS scan_runs (id TEXT PRIMARY KEY, target TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT, status TEXT NOT NULL)")
        db.execute("INSERT INTO scan_runs VALUES (?, ?, ?, NULL, ?)", (run.id, run.target, run.started_at, run.status))
        db.commit()
    return run


def finish_scan(database: str, scan_id: str, status: str) -> None:
    with open_sync_database(database) as db:
        db.execute("UPDATE scan_runs SET completed_at = ?, status = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), status, scan_id))
        db.commit()


_SCAN_RUNS_TABLE = (
    "CREATE TABLE IF NOT EXISTS scan_runs (id TEXT PRIMARY KEY, target TEXT NOT NULL, "
    "started_at TEXT NOT NULL, completed_at TEXT, status TEXT NOT NULL)"
)


def list_scans(database: str, limit: int | None = 50) -> list[ScanRun]:
    """Recorded scan runs, newest first. `limit=None` returns every one.

    A requested limit is honoured as asked; this clamped to 500 silently.
    """
    with open_sync_database(database) as db:
        db.execute(_SCAN_RUNS_TABLE)
        query = "SELECT id, target, started_at, completed_at, status FROM scan_runs ORDER BY started_at DESC"
        if limit is None:
            rows = db.execute(query).fetchall()
        else:
            rows = db.execute(query + " LIMIT ?", (max(1, limit),)).fetchall()
    return [ScanRun(*row) for row in rows]


def count_scans(database: str) -> int:
    """How many scan runs are recorded, whatever a listing chose to show."""
    with open_sync_database(database) as db:
        db.execute(_SCAN_RUNS_TABLE)
        return int(db.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0])


def latest_scan(
    database: str, target: str | None = None, *, completed_only: bool = True
) -> ScanRun | None:
    query = "SELECT id, target, started_at, completed_at, status FROM scan_runs"
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
    with open_sync_database(database) as db:
        row = db.execute(query, params).fetchone()
    return ScanRun(*row) if row else None


def get_scan(database: str, scan_id: str) -> ScanRun | None:
    with open_sync_database(database) as db:
        row = db.execute(
            "SELECT id, target, started_at, completed_at, status FROM scan_runs WHERE id = ?",
            (scan_id,),
        ).fetchone()
    return ScanRun(*row) if row else None
