from __future__ import annotations

import sqlite3
from urllib.parse import urlsplit

from sh4q.scope import ScopeEngine


def scan_fingerprint_endpoints(
    database: str,
    scan_id: str,
    scope: ScopeEngine,
    *,
    limit: int = 200,
) -> list[str]:
    """Return deduplicated, in-scope HTTP endpoints owned by one scan."""

    with sqlite3.connect(database) as db:
        rows = db.execute(
            """SELECT DISTINCT n.value
            FROM scan_assets sa
            JOIN nodes n ON n.id = sa.asset_id
            WHERE sa.scan_run_id = ? AND n.type = 'url'
            ORDER BY n.value""",
            (scan_id,),
        ).fetchall()

    endpoints: list[str] = []
    for (endpoint,) in rows:
        parsed = urlsplit(endpoint)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in {"http", "https"} or not hostname:
            continue
        if not scope.authorize(hostname).allowed:
            continue
        endpoints.append(endpoint)
        if len(endpoints) >= max(1, limit):
            break
    return endpoints
