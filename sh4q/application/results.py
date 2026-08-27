from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ResultRow:
    type: str
    value: str
    attributes: dict


def list_assets(
    database: str,
    *,
    asset_type: str | None = None,
    target: str | None = None,
    limit: int = 100,
) -> list[ResultRow]:
    query = "SELECT type, value, attributes FROM nodes"
    params: list[object] = []
    if asset_type:
        query += " WHERE type = ?"
        params.append(asset_type)
    query += " ORDER BY type, value LIMIT ?"
    params.append(max(1, min(limit, 1000)))
    with sqlite3.connect(database) as db:
        rows = db.execute(query, params).fetchall()
        assets = [ResultRow(row[0], row[1], json.loads(row[2])) for row in rows]
        if target and asset_type == "ip":
            normalized = target.lower().rstrip(".")
            ip_rows = db.execute(
                """
                SELECT DISTINCT ip.type, ip.value, ip.attributes
                FROM relationships r
                JOIN nodes domain ON domain.id = r.from_id
                JOIN nodes ip ON ip.id = r.to_id
                WHERE r.type = 'RESOLVES_TO'
                  AND (domain.value = ? OR domain.value LIKE ?)
                ORDER BY ip.value
                LIMIT ?
                """,
                (normalized, f"%.{normalized}", max(1, min(limit, 1000))),
            ).fetchall()
            return [ResultRow(row[0], row[1], json.loads(row[2])) for row in ip_rows]
    if not target:
        return assets
    normalized = target.lower().rstrip(".")
    return [asset for asset in assets if _matches_target(asset, normalized)]


def _matches_target(asset: ResultRow, target: str) -> bool:
    if asset.type == "domain":
        value = asset.value.lower().rstrip(".")
        return value == target or value.endswith(f".{target}")
    if asset.type == "url":
        hostname = (urlsplit(asset.value).hostname or "").lower().rstrip(".")
        return hostname == target or hostname.endswith(f".{target}")
    return False


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
