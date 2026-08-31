from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from urllib.parse import urlsplit
from sh4q.storage.db import open_sync_database


@dataclass(frozen=True)
class ResultRow:
    type: str
    value: str
    attributes: dict


@dataclass(frozen=True)
class TechnologyObservation:
    endpoint: str
    technology: str
    category: str
    version: str
    confidence: str
    status: int | None
    signal: str
    source: str


def list_technology_observations(
    database: str,
    *,
    target: str | None = None,
    scan_id: str | None = None,
    limit: int = 100,
) -> list[TechnologyObservation]:
    query = """SELECT endpoint.value, technology.value, r.attributes
        FROM relationships r
        JOIN nodes endpoint ON endpoint.id = r.from_id
        JOIN nodes technology ON technology.id = r.to_id"""
    params: list[object] = []
    if scan_id:
        query += " JOIN scan_assets sa ON sa.relationship_id = r.id"
    query += " WHERE r.type = 'DETECTED_TECHNOLOGY'"
    if scan_id:
        query += " AND sa.scan_run_id = ?"
        params.append(scan_id)
    query += " ORDER BY endpoint.value, technology.value"
    normalized = target.lower().rstrip(".") if target else None
    with open_sync_database(database) as db:
        rows = db.execute(query, params).fetchall()
    observations = []
    for endpoint, technology, raw_attributes in rows:
        if normalized and not _matches_target(ResultRow("url", endpoint, {}), normalized):
            continue
        attributes = json.loads(raw_attributes)
        observations.append(TechnologyObservation(
            endpoint=endpoint,
            technology=technology,
            category=attributes.get("category", ""),
            version=attributes.get("version", ""),
            confidence=attributes.get("confidence", ""),
            status=attributes.get("status"),
            signal=attributes.get("raw_observation", ""),
            source=attributes.get("source", ""),
        ))
        if len(observations) >= max(1, min(limit, 1000)):
            break
    return observations


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
    with open_sync_database(database) as db:
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
        if target and asset_type == "technology":
            technology_rows = db.execute(
                """
                SELECT DISTINCT technology.type, technology.value, technology.attributes
                FROM relationships r
                JOIN nodes endpoint ON endpoint.id = r.from_id
                JOIN nodes technology ON technology.id = r.to_id
                WHERE r.type = 'DETECTED_TECHNOLOGY'
                  AND endpoint.type = 'url'
                ORDER BY technology.value
                """
            ).fetchall()
            technologies = [
                ResultRow(row[0], row[1], json.loads(row[2]))
                for row in technology_rows
            ]
            return [
                item for item in technologies
                if any(
                    _matches_target(url, normalized)
                    for url in _technology_endpoints(db, item.value)
                )
            ][: max(1, min(limit, 1000))]
    return assets


def _technology_endpoints(db: sqlite3.Connection, technology: str) -> list[ResultRow]:
    rows = db.execute(
        """SELECT endpoint.type, endpoint.value, endpoint.attributes
        FROM relationships r
        JOIN nodes endpoint ON endpoint.id = r.from_id
        JOIN nodes technology_node ON technology_node.id = r.to_id
        WHERE r.type = 'DETECTED_TECHNOLOGY' AND technology_node.value = ?""",
        (technology,),
    ).fetchall()
    return [ResultRow(row[0], row[1], json.loads(row[2])) for row in rows]


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
    with open_sync_database(database) as db:
        return db.execute(query, params).fetchall()
