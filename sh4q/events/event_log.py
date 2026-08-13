

import json

import aiosqlite

from .event import Event


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
                    updated_at TEXT NOT NULL
                )
                """
            )
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

    async def _set_status(self, event_id: str, status: str) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "UPDATE event_log SET status = ?, updated_at = ? WHERE id = ?",
                (status, _iso_now(), event_id),
            )
            await db.commit()

    async def recover_unfinished(self) -> list[Event]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM event_log WHERE status != 'COMPLETED' ORDER BY created_at ASC"
            )
            rows = await cursor.fetchall()
            return [
                Event(id=row["id"], type=row["type"], payload=json.loads(row["payload"]), timestamp=row["created_at"])
                for row in rows
            ]


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()