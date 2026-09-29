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


@dataclass(frozen=True)
class TechnologySummary:
    technology: str
    version: str
    category: str
    source: str
    endpoints: int


@dataclass(frozen=True)
class JavaScriptObservation:
    kind: str
    value: str
    source_endpoint: str
    captured_at: str


SOURCE_ALIASES = {
    "native": "offline-http-signatures",
    "httpx": "httpx-fingerprint",
}


def friendly_technology_source(source: str) -> str:
    return {
        "offline-http-signatures": "native",
        "httpx-fingerprint": "httpx",
    }.get(source, source)


def list_javascript_observations(
    database: str,
    *,
    scan_id: str | None = None,
    kind: str | None = None,
    source_filter: str | None = None,
    limit: int = 100,
) -> list[JavaScriptObservation]:
    query = "SELECT kind, content, captured_at FROM evidence WHERE kind LIKE 'javascript_%'"
    params: list[object] = []
    if scan_id:
        query += " AND scan_run_id = ?"
        params.append(scan_id)
    if kind:
        query += " AND kind = ?"
        params.append(f"javascript_{kind}")
    query += " ORDER BY captured_at, kind LIMIT ?"
    params.append(max(1, min(limit, 1000)))
    with open_sync_database(database) as db:
        rows = db.execute(query, params).fetchall()
    observations = []
    seen: set[tuple[str, str, str]] = set()
    for kind, raw_content, captured_at in rows:
        content = json.loads(raw_content)
        value = content.get("value", "")
        source_endpoint = content.get("source_endpoint", "")
        if source_filter and source_filter.lower() not in source_endpoint.lower():
            continue
        key = (kind, value, source_endpoint.rstrip("/") or source_endpoint)
        if key in seen:
            continue
        seen.add(key)
        observations.append(JavaScriptObservation(kind, value, source_endpoint, captured_at))
    return observations


def list_technology_observations(
    database: str,
    *,
    target: str | None = None,
    scan_id: str | None = None,
    source: str | None = None,
    category: str | None = None,
    status: int | None = None,
    limit: int | None = 100,
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
        resolved_source = SOURCE_ALIASES.get(source, source) if source else None
        if resolved_source and attributes.get("source") != resolved_source:
            continue
        if category and attributes.get("category") != category:
            continue
        if status is not None and attributes.get("status") != status:
            continue
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
        if limit is not None and len(observations) >= max(1, limit):
            break
    return observations


def summarize_technology_observations(rows: list[TechnologyObservation]) -> list[TechnologySummary]:
    grouped: dict[tuple[str, str, str, str], set[str]] = {}
    for row in rows:
        key = (row.technology, row.version, row.category, friendly_technology_source(row.source))
        grouped.setdefault(key, set()).add(row.endpoint)
    summaries = [
        TechnologySummary(technology, version, category, source, len(endpoints))
        for (technology, version, category, source), endpoints in grouped.items()
    ]
    return sorted(summaries, key=lambda item: (-item.endpoints, item.technology, item.source))


def list_assets(
    database: str,
    *,
    asset_type: str | None = None,
    target: str | None = None,
    scan_id: str | None = None,
    source: str | None = None,
    limit: int = 100,
) -> list[ResultRow]:
    query = "SELECT DISTINCT n.type, n.value, n.attributes FROM nodes n"
    params: list[object] = []
    conditions: list[str] = []
    if scan_id and source:
        query += " JOIN scan_assets sa ON sa.asset_id = n.id AND sa.scan_run_id = ?"
        params.append(scan_id)
        conditions.append("sa.source_plugin = ?")
        params.append(source)
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
            source_clause = ""
            source_params: tuple[object, ...] = ()
            if source:
                source_clause = " AND sa.source_plugin = ?"
                source_params = (source,)
            scan_rows = db.execute(
                """SELECT DISTINCT n.type, n.value, n.attributes
                FROM scan_assets sa JOIN nodes n ON n.id = sa.asset_id
                WHERE sa.scan_run_id = ? AND (? IS NULL OR n.type = ?)
                """ + source_clause + """
                ORDER BY n.type, n.value LIMIT ?""",
                (scan_id, asset_type, asset_type, *source_params, max(1, min(limit, 1000))),
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


def list_failures(
    database: str,
    *,
    target: str | None = None,
    scan_id: str | None = None,
    limit: int = 100,
) -> list[tuple[str, str, str]]:
    query = "SELECT plugin, kind, content FROM evidence WHERE (kind LIKE '%error%' OR kind IN ('adapter_execution', 'ct_provider_status'))"
    params: list[object] = []
    if target:
        query += " AND target = ?"
        params.append(target)
    if scan_id:
        query += " AND scan_run_id = ?"
        params.append(scan_id)
    query += " ORDER BY captured_at DESC LIMIT 1000"
    with open_sync_database(database) as db:
        rows = db.execute(query, params).fetchall()
    failures: list[tuple[str, str, str]] = []
    for plugin, kind, content in rows:
        details = json.loads(content)
        if kind == "adapter_execution" and not (
            details.get("returncode") not in (None, 0)
            or details.get("timed_out")
            or details.get("output_limited")
        ):
            continue
        if kind == "ct_provider_status" and details.get("status") == "success":
            continue
        failures.append((plugin, kind, content))
        if len(failures) >= max(1, min(limit, 1000)):
            break
    return failures


@dataclass(frozen=True)
class ResponseAttributes:
    """Cookie flags and review headers recorded for one endpoint."""

    url: str
    cookies: tuple[dict, ...]
    security_headers: dict[str, str]

    @property
    def missing_headers(self) -> tuple[str, ...]:
        return tuple(name for name, value in sorted(self.security_headers.items()) if not value)


def list_response_attributes(
    database: str,
    *,
    target: str | None = None,
    scan_id: str | None = None,
    limit: int | None = None,
) -> list[ResponseAttributes]:
    """Endpoints that set a cookie or were checked for review headers.

    Sh4q records what the server sent. It does not decide whether a missing
    flag matters, because that depends on the application.
    """
    # Every endpoint, not a page of them: this view groups and counts, and a
    # count that stopped at the display limit reported 87 of 228.
    values = _all_asset_values(database, "url", target=target, scan_id=scan_id)
    with open_sync_database(database) as db:
        attribute_rows = dict(db.execute("SELECT value, attributes FROM nodes WHERE type = 'url'").fetchall())
    rows = [
        ResultRow("url", value, json.loads(attribute_rows.get(value) or "{}"))
        for value in values
    ]
    if limit is not None:
        rows = rows[: max(1, limit)]
    found: list[ResponseAttributes] = []
    for row in rows:
        attributes = row.attributes or {}
        cookies = attributes.get("cookies") or []
        headers = attributes.get("security_headers") or {}
        if not cookies and not headers:
            continue
        found.append(ResponseAttributes(row.value, tuple(cookies), dict(headers)))
    return found


# Leftmost labels that hosting panels and mail providers commonly request
# certificates for automatically. Their presence is a hint, not a verdict:
# an organisation may genuinely run mail.example.com.
AUTO_ISSUED_LABELS = frozenset({
    "cpanel", "webmail", "webdisk", "mail", "autodiscover",
    "cpcalendars", "cpcontacts", "autoconfig", "mta-sts",
})


@dataclass(frozen=True)
class NameComposition:
    """What a scan's hostnames are made of, and how many proved real."""

    total: int
    resolved: int
    unresolved: int
    unchecked: int
    auto_issued: int
    auto_issued_resolved: int
    label_counts: tuple[tuple[str, int], ...]

    @property
    def auto_issued_share(self) -> int:
        return round(self.auto_issued * 100 / self.total) if self.total else 0


def _all_asset_values(database: str, asset_type: str, *, target: str | None, scan_id: str | None) -> list[str]:
    """Every asset of a type, with no display cap.

    list_assets caps at 1000 because it feeds a terminal listing. A summary
    counts rather than lists, and a count that silently stops at 1000 is
    worse than no count: a scan of 1209 names reported 1000 and looked
    complete.
    """
    with open_sync_database(database) as db:
        if scan_id:
            rows = db.execute(
                """SELECT DISTINCT n.value FROM nodes n
                   JOIN scan_assets s ON s.asset_id = n.id
                   WHERE s.scan_run_id = ? AND n.type = ?""",
                (scan_id, asset_type),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT DISTINCT value FROM nodes WHERE type = ?", (asset_type,)
            ).fetchall()
    values = [row[0] for row in rows]
    if target:
        normalized = target.lower().rstrip(".")
        values = [
            value
            for value in values
            if _matches_target(ResultRow(asset_type, value, {}), normalized)
        ]
    return sorted(values)


def summarize_names(
    database: str,
    *,
    target: str | None = None,
    scan_id: str | None = None,
) -> NameComposition:
    """Break a scan's hostnames down by resolution outcome and leftmost label.

    Certificate transparency returns every name a certificate was issued for.
    Hosting panels request certificates for service subdomains on every hosted
    domain, so a large share of a CT result can be names that were never
    deployed. Crossing the label against whether the name resolved is what
    separates the two, and doing it by hand is tedious enough to be skipped.
    """
    domains = _all_asset_values(database, "domain", target=target, scan_id=scan_id)
    resolved: set[str] = set()
    failed: set[str] = set()
    with open_sync_database(database) as db:
        for kind, content in db.execute(
            "SELECT kind, content FROM evidence WHERE kind IN "
            "('dns_resolution', 'discovered_dns_resolution', 'discovered_dns_error')"
        ):
            try:
                name = json.loads(content).get("domain", "")
            except (TypeError, ValueError):
                continue
            if not name:
                continue
            (failed if kind == "discovered_dns_error" else resolved).add(name.lower())
    failed -= resolved

    labels: dict[str, int] = {}
    auto = auto_resolved = 0
    for name in domains:
        label = name.split(".", 1)[0].lower()
        labels[label] = labels.get(label, 0) + 1
        if label in AUTO_ISSUED_LABELS:
            auto += 1
            if name.lower() in resolved:
                auto_resolved += 1

    checked = {name for name in domains if name.lower() in resolved or name.lower() in failed}
    return NameComposition(
        total=len(domains),
        resolved=sum(1 for n in domains if n.lower() in resolved),
        unresolved=sum(1 for n in domains if n.lower() in failed),
        unchecked=len(domains) - len(checked),
        auto_issued=auto,
        auto_issued_resolved=auto_resolved,
        label_counts=tuple(sorted(labels.items(), key=lambda kv: (-kv[1], kv[0]))[:8]),
    )
