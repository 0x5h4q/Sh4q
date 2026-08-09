
"""
sh4q/storage/sqlite_storage.py

The ONE place in the whole engine that knows SQL exists. Everything else
talks to StorageRepository's Node/Relationship vocabulary; this class is
what translates that into two plain relational tables underneath.

This is the repository pattern in practice: swapping SQLite for Postgres
later means writing a new class that implements the same four methods —
nothing in the Scheduler, plugins, or anywhere else has to change.
"""

import json

import aiosqlite

from .models import Node, Relationship


class SQLiteStorage:
    def __init__(self, db_path: str):
        self._db_path = db_path

    async def init(self) -> None:
        """Create tables if they don't exist. Call once at startup."""
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS nodes (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    attributes TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                )
                """
            )
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS relationships (
                    id TEXT PRIMARY KEY,
                    from_id TEXT NOT NULL,
                    to_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    attributes TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            await db.commit()

    async def save_node(self, node: Node) -> Node:
        existing = await self.get_node(node.id)
        async with aiosqlite.connect(self._db_path) as db:
            if existing:
                # Merge, don't overwrite — this is the "asset store enriches
                # over time" behavior. Existing attributes win on conflict
                # only if the new node didn't provide a fresher value.
                merged = {**existing.attributes, **node.attributes}
                await db.execute(
                    "UPDATE nodes SET attributes = ?, last_seen = ? WHERE id = ?",
                    (json.dumps(merged), node.last_seen, node.id),
                )
                node.attributes = merged
                node.first_seen = existing.first_seen  # preserve original discovery time
            else:
                await db.execute(
                    "INSERT INTO nodes (id, type, value, attributes, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (node.id, node.type, node.value, json.dumps(node.attributes),
                     node.first_seen, node.last_seen),
                )
            await db.commit()
        return node

    async def get_node(self, node_id: str) -> Node | None:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM nodes WHERE id = ?", (node_id,))
            row = await cursor.fetchone()
            if row is None:
                return None
            return Node(
                type=row["type"],
                value=row["value"],
                attributes=json.loads(row["attributes"]),
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
            )

    async def save_relationship(self, relationship: Relationship) -> Relationship:
        async with aiosqlite.connect(self._db_path) as db:
            # INSERT OR IGNORE: re-saving an identical relationship
            # (same deterministic id) is a no-op, not an error or a duplicate.
            await db.execute(
                "INSERT OR IGNORE INTO relationships "
                "(id, from_id, to_id, type, attributes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (relationship.id, relationship.from_id, relationship.to_id,
                 relationship.type, json.dumps(relationship.attributes), relationship.created_at),
            )
            await db.commit()
        return relationship

    async def get_relationships(self, node_id: str) -> list[Relationship]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM relationships WHERE from_id = ? OR to_id = ?",
                (node_id, node_id),
            )
            rows = await cursor.fetchall()
            return [
                Relationship(
                    from_id=row["from_id"],
                    to_id=row["to_id"],
                    type=row["type"],
                    attributes=json.loads(row["attributes"]),
                    created_at=row["created_at"],
                )
                for row in rows
            ]