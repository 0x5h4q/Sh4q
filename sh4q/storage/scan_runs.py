from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4


@dataclass(frozen=True)
class ScanRun:
    id: str
    target: str
    started_at: str
    completed_at: str | None
    status: str


def create_scan(database: str, target: str) -> ScanRun:
    started = datetime.now(timezone.utc).isoformat()
    run = ScanRun(uuid4().hex, target, started, None, "RUNNING")
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE IF NOT EXISTS scan_runs (id TEXT PRIMARY KEY, target TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT, status TEXT NOT NULL)")
        db.execute("INSERT INTO scan_runs VALUES (?, ?, ?, NULL, ?)", (run.id, run.target, run.started_at, run.status))
        db.commit()
    return run


def finish_scan(database: str, scan_id: str, status: str) -> None:
    with sqlite3.connect(database) as db:
        db.execute("UPDATE scan_runs SET completed_at = ?, status = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), status, scan_id))
        db.commit()


def list_scans(database: str, limit: int = 50) -> list[ScanRun]:
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE IF NOT EXISTS scan_runs (id TEXT PRIMARY KEY, target TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT, status TEXT NOT NULL)")
        rows = db.execute("SELECT id, target, started_at, completed_at, status FROM scan_runs ORDER BY started_at DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall()
    return [ScanRun(*row) for row in rows]
