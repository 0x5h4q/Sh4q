from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class ResultRow:
    type: str
    value: str
    attributes: dict


def list_assets(database: str, *, asset_type: str | None = None, limit: int = 100) -> list[ResultRow]:
    query = "SELECT type, value, attributes FROM nodes"
    params: list[object] = []
    if asset_type:
        query += " WHERE type = ?"
        params.append(asset_type)
    query += " ORDER BY type, value LIMIT ?"
    params.append(max(1, min(limit, 1000)))
    with sqlite3.connect(database) as db:
        rows = db.execute(query, params).fetchall()
    return [ResultRow(row[0], row[1], json.loads(row[2])) for row in rows]


def list_failures(database: str, *, target: str | None = None, limit: int = 100) -> list[tuple[str, str, str]]:
    query = "SELECT plugin, kind, content FROM evidence WHERE kind LIKE '%error%' OR kind IN ('adapter_execution', 'ct_provider_status')"
    params: list[object] = []
    if target:
        query += " AND target = ?"
        params.append(target)
    query += " ORDER BY captured_at DESC LIMIT ?"
    params.append(max(1, min(limit, 1000)))
    with sqlite3.connect(database) as db:
        return db.execute(query, params).fetchall()
