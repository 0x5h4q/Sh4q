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
    scan_id: str | None = None,
    limit: int = 100,
) -> list[ResultRow]:
    query = "SELECT type, value, attributes FROM nodes"
    params: list[object] = []
    conditions: list[str] = []
    if asset_type:
        conditions.append("type = ?")
        params.append(asset_type)
    normalized = target.lower().rstrip(".") if target else None
    if normalized and asset_type == "domain":
        conditions.append("(lower(rtrim(value, '.')) = ? OR lower(rtrim(value, '.')) LIKE ?)")
        params.extend((normalized, f"%.{normalized}"))
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY type, value LIMIT ?"
    params.append(max(1, min(limit, 1000)))
    with sqlite3.connect(database) as db:
        if scan_id:
            scan_rows = db.execute(
                """SELECT DISTINCT n.type, n.value, n.attributes
                FROM scan_assets sa JOIN nodes n ON n.id = sa.asset_id
                WHERE sa.scan_run_id = ? AND (? IS NULL OR n.type = ?)
                ORDER BY n.type, n.value LIMIT ?""",
                (scan_id, asset_type, asset_type, max(1, min(limit, 1000))),
            ).fetchall()
            return [ResultRow(row[0], row[1], json.loads(row[2])) for row in scan_rows]
        if normalized and asset_type == "url":
            # SQLite has no built-in URL hostname parser, so filter URLs before
            # applying the user-visible limit.
            url_rows = db.execute(
                "SELECT type, value, attributes FROM nodes WHERE type = 'url' ORDER BY value"
            ).fetchall()
            assets = [ResultRow(row[0], row[1], json.loads(row[2])) for row in url_rows]
            return [asset for asset in assets if _matches_target(asset, normalized)][: max(1, min(limit, 1000))]
        rows = db.execute(query, params).fetchall()
        assets = [ResultRow(row[0], row[1], json.loads(row[2])) for row in rows]
        if target and asset_type == "ip":
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
    return assets


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
