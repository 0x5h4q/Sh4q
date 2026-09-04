
import json

import aiosqlite

from .models import Node, Relationship
from .db import ensure_schema_version, open_database


class SQLiteStorage:
    def __init__(self, db_path: str):
        self._db_path = db_path

    async def init(self) -> None:
        """Create tables if they don't exist. Call once at startup."""
        ensure_schema_version(self._db_path)
        async with open_database(self._db_path) as db:
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
        async with open_database(self._db_path) as db:
            await db.execute(
                """
                INSERT INTO nodes (id, type, value, attributes, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    attributes = json_patch(nodes.attributes, excluded.attributes),
                    last_seen = excluded.last_seen
                """,
                (node.id, node.type, node.value, json.dumps(node.attributes),
                 node.first_seen, node.last_seen),
            )
            await db.commit()
        # Read back the current state so the caller gets what's actually stored (including merged attributes and the true first_seen).
        return await self.get_node(node.id)

    async def save_nodes_batch(self, nodes: list[Node]) -> None:
        if not nodes:
            return
        async with open_database(self._db_path) as db:
            await db.executemany(
                """INSERT INTO nodes (id, type, value, attributes, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    attributes = json_patch(nodes.attributes, excluded.attributes),
                    last_seen = excluded.last_seen""",
                [(node.id, node.type, node.value, json.dumps(node.attributes), node.first_seen, node.last_seen) for node in nodes],
            )
            await db.commit()

    async def get_node(self, node_id: str) -> Node | None:
        async with open_database(self._db_path) as db:
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
        async with open_database(self._db_path) as db:
            await db.execute(
                "INSERT OR IGNORE INTO relationships "
                "(id, from_id, to_id, type, attributes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (relationship.id, relationship.from_id, relationship.to_id,
                 relationship.type, json.dumps(relationship.attributes), relationship.created_at),
            )
            await db.commit()
        return relationship

    async def save_relationships_batch(self, relationships: list[Relationship]) -> None:
        if not relationships:
            return
        async with open_database(self._db_path) as db:
            await db.executemany(
                "INSERT OR IGNORE INTO relationships (id, from_id, to_id, type, attributes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                [(item.id, item.from_id, item.to_id, item.type, json.dumps(item.attributes), item.created_at) for item in relationships],
            )
            await db.commit()

    async def get_relationships(self, node_id: str) -> list[Relationship]:
        async with open_database(self._db_path) as db:
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
