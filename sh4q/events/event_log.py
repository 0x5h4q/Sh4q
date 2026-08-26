

import json
from dataclasses import dataclass
from datetime import datetime, timezone

import aiosqlite

from .event import Event


@dataclass(frozen=True)
class EventLogRecord:
    id: str
    type: str
    status: str
    attempts: int
    error: str | None
    created_at: str
    updated_at: str
    next_attempt_at: str | None


class DurableEventLog:
    def __init__(self, db_path: str):
        self._db_path = db_path

    async def init(self) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS event_log (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    error TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at TEXT
                )
                """
            )
            columns = await (await db.execute("PRAGMA table_info(event_log)")).fetchall()
            if not any(row[1] == "error" for row in columns):
                await db.execute("ALTER TABLE event_log ADD COLUMN error TEXT")
            if not any(row[1] == "attempts" for row in columns):
                await db.execute("ALTER TABLE event_log ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
            if not any(row[1] == "next_attempt_at" for row in columns):
                await db.execute("ALTER TABLE event_log ADD COLUMN next_attempt_at TEXT")
            await db.commit()

    async def record_pending(self, event: Event) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT INTO event_log (id, type, payload, status, created_at, updated_at) "
                "VALUES (?, ?, ?, 'PENDING', ?, ?)",
                (event.id, event.type, json.dumps(event.payload), event.timestamp, event.timestamp),
            )
            await db.commit()

    async def mark_processing(self, event_id: str) -> None:
        await self._set_status(event_id, "PROCESSING")

    async def mark_completed(self, event_id: str) -> None:
        await self._set_status(event_id, "COMPLETED")

    async def mark_failed(self, event_id: str, error: str, *, max_attempts: int = 3, retry_delay: float = 0.0) -> bool:
        next_attempt = datetime.now(timezone.utc).timestamp() + max(0.0, retry_delay)
        async with aiosqlite.connect(self._db_path) as db:
            row = await (await db.execute("SELECT attempts FROM event_log WHERE id = ?", (event_id,))).fetchone()
            attempts = (row[0] if row else 0) + 1
            status = "DEAD_LETTER" if attempts >= max_attempts else "FAILED"
            await db.execute(
                "UPDATE event_log SET status = ?, updated_at = ?, error = ?, attempts = ?, next_attempt_at = ? WHERE id = ?",
                (status, _iso_now(), error, attempts, _iso_from_timestamp(next_attempt) if status == "FAILED" else None, event_id),
            )
            await db.commit()
        return status == "FAILED"

    async def _set_status(self, event_id: str, status: str, error: str | None = None) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "UPDATE event_log SET status = ?, updated_at = ?, error = ? WHERE id = ?",
                (status, _iso_now(), error, event_id),
            )
            await db.commit()

    async def recover_unfinished(self) -> list[Event]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM event_log WHERE status IN ('PENDING', 'PROCESSING', 'FAILED') AND (next_attempt_at IS NULL OR next_attempt_at <= ?) ORDER BY created_at ASC",
                (_iso_now(),),
            )
            rows = await cursor.fetchall()
            return [
                Event(id=row["id"], type=row["type"], payload=json.loads(row["payload"]), timestamp=row["created_at"])
                for row in rows
            ]

    async def list_records(
        self,
        *,
        status: str | None = None,
        limit: int = 50,
    ) -> list[EventLogRecord]:
        query = "SELECT * FROM event_log"
        parameters: list[object] = []
        if status:
            query += " WHERE status = ?"
            parameters.append(status.upper())
        query += " ORDER BY updated_at DESC LIMIT ?"
        parameters.append(max(1, min(limit, 500)))
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            rows = await (await db.execute(query, parameters)).fetchall()
        return [
            EventLogRecord(
                id=row["id"],
                type=row["type"],
                status=row["status"],
                attempts=row["attempts"],
                error=row["error"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                next_attempt_at=row["next_attempt_at"],
            )
            for row in rows
        ]


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso_from_timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()
