

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

import aiosqlite

from sh4q.storage.db import open_database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Evidence:
    id: str              
    target: str
    plugin: str
    kind: str
    content: dict
    captured_at: str = field(default_factory=_now)


class EvidenceStore(Protocol):
    async def append(self, evidence: Evidence) -> None: ...
    async def get(self, evidence_id: str) -> Evidence | None: ...
    async def list_for_target(
        self, target: str, *, captured_after: str | None = None
    ) -> list[Evidence]: ...


class SQLiteEvidenceStore:
    def __init__(self, db_path: str):
        self._db_path = db_path

    async def init(self) -> None:
        async with open_database(self._db_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    plugin TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    content TEXT NOT NULL,
                    captured_at TEXT NOT NULL
                )
                """
            )
            await db.commit()

    async def append(self, evidence: Evidence) -> None:
        async with open_database(self._db_path) as db:
            await db.execute(
                "INSERT OR IGNORE INTO evidence (id, target, plugin, kind, content, captured_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (evidence.id, evidence.target, evidence.plugin, evidence.kind,
                 json.dumps(evidence.content), evidence.captured_at),
            )
            await db.commit()

    async def get(self, evidence_id: str) -> Evidence | None:
        async with open_database(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
            row = await cursor.fetchone()
            if row is None:
                return None
            return Evidence(
                id=row["id"], target=row["target"], plugin=row["plugin"], kind=row["kind"],
                content=json.loads(row["content"]), captured_at=row["captured_at"],
            )

    async def list_for_target(self, target: str, *, captured_after: str | None = None) -> list[Evidence]:
        async with open_database(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            if captured_after is None:
                cursor = await db.execute(
                    "SELECT * FROM evidence WHERE target = ? ORDER BY captured_at ASC", (target,)
                )
            else:
                cursor = await db.execute(
                    "SELECT * FROM evidence WHERE target = ? AND captured_at >= ? ORDER BY captured_at ASC",
                    (target, captured_after),
                )
            rows = await cursor.fetchall()
            return [
                Evidence(
                    id=row["id"], target=row["target"], plugin=row["plugin"], kind=row["kind"],
                    content=json.loads(row["content"]), captured_at=row["captured_at"],
                )
                for row in rows
            ]
