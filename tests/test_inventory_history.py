import argparse
import contextlib
import csv
import io
import json
import sqlite3
import tempfile
from pathlib import Path

from sh4q.application.exporter import export_scan
from sh4q.application.html_report import render_html_report
from sh4q.application.results import list_assets, list_inventory_history
from sh4q.cli.main import build_parser, render_inventory_history
from sh4q.storage.scan_runs import ScanRun


SCHEMA = """
CREATE TABLE nodes (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    attributes TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE relationships (
    id TEXT PRIMARY KEY,
    from_id TEXT NOT NULL,
    to_id TEXT NOT NULL,
    type TEXT NOT NULL,
    attributes TEXT NOT NULL
);
CREATE TABLE scan_assets (
    scan_run_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    relationship_id TEXT NOT NULL,
    source_plugin TEXT NOT NULL
);
CREATE TABLE scan_runs (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL
);
CREATE TABLE evidence (
    id TEXT PRIMARY KEY,
    target TEXT,
    plugin TEXT,
    kind TEXT,
    content TEXT,
    captured_at TEXT,
    scan_run_id TEXT
);
"""


def _insert(db, table, columns, rows):
    placeholders = ", ".join("?" for _ in columns)
    db.executemany(
        f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})", rows
    )


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    database = str(root / "history.db")
    with sqlite3.connect(database) as db:
        db.executescript(SCHEMA)

        # The same asset appears in both scans. Its first_seen predates both,
        # which is exactly the graph history a scan must not overwrite.
        _insert(db, "nodes", (
            "id", "type", "value", "attributes", "first_seen", "last_seen",
        ), [
            ("domain:api.example.com", "domain", "api.example.com", "{}",
             "2025-12-31T12:00:00+00:00", "2026-02-10T12:00:00+00:00"),
            ("domain:new.example.com", "domain", "new.example.com", "{}",
             "2026-02-01T00:00:01+00:00", "2026-02-10T12:00:00+00:00"),
            ("domain:old-only.example.com", "domain", "old-only.example.com", "{}",
             "2025-12-01T12:00:00+00:00", "2026-01-01T00:00:01+00:00"),
            ("domain:other.test", "domain", "other.test", "{}",
             "2026-01-15T12:00:00+00:00", "2026-02-10T12:00:00+00:00"),
            ("url:https://api.example.com/", "url", "https://api.example.com/",
             '{"status":200}',
             "2026-01-15T12:00:00+00:00", "2026-02-10T12:00:00+00:00"),
            ("technology:nginx", "technology", "nginx",
             '{"category":"web-server","version":"1.25","confidence":"explicit",'
             '"status":200,"raw_observation":"header:server=nginx","source":"native"}',
             "2026-01-15T12:00:00+00:00", "2026-02-10T12:00:00+00:00"),
            ("ip:93.184.216.34", "ip", "93.184.216.34", "{}",
             "2026-01-15T12:00:00+00:00", "2026-02-10T12:00:00+00:00"),
        ])

        _insert(db, "relationships", (
            "id", "from_id", "to_id", "type", "attributes",
        ), [
            ("rel-serves", "domain:api.example.com", "url:https://api.example.com/",
             "SERVES", "{}"),
            ("rel-tech", "url:https://api.example.com/", "technology:nginx",
             "DETECTED_TECHNOLOGY",
             '{"category":"web-server","version":"1.25","confidence":"explicit",'
             '"status":200,"raw_observation":"header:server=nginx","source":"native"}'),
            ("rel-dns", "domain:api.example.com", "ip:93.184.216.34",
             "RESOLVES_TO", "{}"),
        ])

        _insert(db, "scan_assets", (
            "scan_run_id", "asset_id", "relationship_id", "source_plugin",
        ), [
            ("scan-old", "domain:api.example.com", "rel-old-api", "subfinder"),
            ("scan-old", "domain:old-only.example.com", "rel-old-only", "subfinder"),
            ("scan-old", "url:https://api.example.com/", "rel-serves", "http"),
            ("scan-new", "domain:api.example.com", "rel-new-api", "subfinder"),
            ("scan-new", "domain:new.example.com", "rel-new-ct", "ct"),
            ("scan-new", "url:https://api.example.com/", "rel-serves", "http"),
            ("scan-new", "technology:nginx", "rel-tech", "native"),
            ("scan-new", "ip:93.184.216.34", "rel-dns", "dns"),
            ("scan-other", "domain:other.test", "rel-other", "subfinder"),
        ])

        _insert(db, "scan_runs", (
            "id", "target", "started_at", "completed_at", "status",
        ), [
            ("scan-old", "example.com", "2026-01-01T00:00:00+00:00",
             "2026-01-01T01:00:00+00:00", "COMPLETED"),
            ("scan-new", "example.com", "2026-02-01T00:00:00+00:00",
             "2026-02-01T01:00:00+00:00", "COMPLETED"),
            ("scan-other", "other.test", "2026-01-15T00:00:00+00:00",
             "2026-01-15T01:00:00+00:00", "COMPLETED"),
        ])

    # Global history: every asset, newest first, with graph-wide timestamps.
    history = list_inventory_history(database)
    by_value = {row.value: row for row in history}
    assert by_value["api.example.com"].first_seen == "2025-12-31T12:00:00+00:00"
    assert by_value["api.example.com"].last_seen == "2026-02-10T12:00:00+00:00"
    assert by_value["api.example.com"].origin == ""
    assert by_value["new.example.com"].first_seen == "2026-02-01T00:00:01+00:00"
    assert by_value["old-only.example.com"].first_seen == "2025-12-01T12:00:00+00:00"
    assert "other.test" in by_value
    first_seens = [row.first_seen for row in history]
    assert first_seens == sorted(first_seens, reverse=True), first_seens

    # A scan owns the rows it discovered, not the history of those rows.
    scan_history = list_inventory_history(database, scan_id="scan-new")
    scan_values = {row.value for row in scan_history}
    assert "api.example.com" in scan_values
    assert "new.example.com" in scan_values
    assert "old-only.example.com" not in scan_values
    assert "https://api.example.com/" in scan_values
    assert "nginx" in scan_values
    assert "93.184.216.34" in scan_values
    assert "other.test" not in scan_values

    returning = next(row for row in scan_history if row.value == "api.example.com")
    new = next(row for row in scan_history if row.value == "new.example.com")
    assert returning.origin == "returning"
    assert new.origin == "new"
    # The timestamp stays graph-wide even when classification is scan-relative.
    assert returning.first_seen == "2025-12-31T12:00:00+00:00"
    assert new.first_seen == "2026-02-01T00:00:01+00:00"

    ct_only = list_inventory_history(database, scan_id="scan-new", source="ct")
    assert [row.value for row in ct_only] == ["new.example.com"]

    # Target and type filters read the same inventory.
    filtered = list_inventory_history(database, asset_type="domain", target="example.com")
    assert {row.value for row in filtered} == {
        "api.example.com", "new.example.com", "old-only.example.com",
    }
    assert all(row.value.endswith("example.com") for row in filtered)

    limited = list_inventory_history(database, limit=2)
    assert len(limited) == 2
    assert [row.first_seen for row in limited] == first_seens[:2]

    # Nodes without timestamp columns are readable and honestly empty.
    legacy = str(root / "legacy.db")
    with sqlite3.connect(legacy) as db:
        db.executescript(
            "CREATE TABLE nodes (id TEXT, type TEXT, value TEXT, attributes TEXT);"
            "CREATE TABLE relationships (id TEXT, from_id TEXT, to_id TEXT, type TEXT, attributes TEXT);"
            "CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT);"
            "CREATE TABLE scan_runs (id TEXT, target TEXT, started_at TEXT, completed_at TEXT, status TEXT);"
            "CREATE TABLE evidence (id TEXT, target TEXT, plugin TEXT, kind TEXT, content TEXT, captured_at TEXT, scan_run_id TEXT);"
        )
        db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)", (
            "domain:legacy.example.com", "domain", "legacy.example.com", "{}",
        ))
        db.execute("INSERT INTO scan_assets VALUES (?, ?, ?, ?)", (
            "legacy-scan", "domain:legacy.example.com", "rel-legacy", "subfinder",
        ))
        db.execute("INSERT INTO scan_runs VALUES (?, ?, ?, ?, ?)", (
            "legacy-scan", "legacy.example.com",
            "2026-01-01T00:00:00+00:00", "2026-01-01T01:00:00+00:00", "COMPLETED",
        ))
    legacy_assets = list_assets(legacy, scan_id="legacy-scan")
    assert legacy_assets[0].first_seen == ""
    assert legacy_assets[0].last_seen == ""
    legacy_history = list_inventory_history(legacy, scan_id="legacy-scan")
    assert legacy_history[0].origin == "unknown"
    legacy_json = root / "legacy.json"
    export_scan(
        legacy,
        ScanRun("legacy-scan", "legacy.example.com", "start", "end", "COMPLETED"),
        format="json",
        output=legacy_json,
    )
    legacy_asset = json.loads(legacy_json.read_text())["assets"][0]
    assert legacy_asset["first_seen"] == ""
    assert legacy_asset["last_seen"] == ""

    # Exports carry the same timestamps as the results view.
    run = ScanRun("scan-new", "example.com", "start", "end", "COMPLETED")
    json_path = root / "history.json"
    export_scan(database, run, format="json", output=json_path)
    document = json.loads(json_path.read_text())
    exported = {item["value"]: item for item in document["assets"]}
    assert exported["api.example.com"]["first_seen"] == "2025-12-31T12:00:00+00:00"
    assert exported["api.example.com"]["last_seen"] == "2026-02-10T12:00:00+00:00"
    assert "old-only.example.com" not in exported

    csv_path = root / "history.csv"
    export_scan(database, run, format="csv", output=csv_path)
    with csv_path.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    csv_by_value = {row["value"]: row for row in rows}
    assert csv_by_value["api.example.com"]["first_seen"] == "2025-12-31T12:00:00+00:00"
    assert csv_by_value["api.example.com"]["last_seen"] == "2026-02-10T12:00:00+00:00"

    technology_path = root / "technologies.csv"
    export_scan(
        database, run, format="csv", output=technology_path, asset_type="technology"
    )
    with technology_path.open(newline="") as stream:
        technology_rows = list(csv.DictReader(stream))
    assert technology_rows[0]["technology"] == "nginx"
    assert technology_rows[0]["first_seen"] == "2026-01-15T12:00:00+00:00"

    inventory_path = root / "inventory.csv"
    export_scan(
        database, run, format="csv", output=inventory_path,
        asset_type="http-inventory",
    )
    with inventory_path.open(newline="") as stream:
        inventory_rows = list(csv.DictReader(stream))
    assert inventory_rows[0]["endpoint"] == "https://api.example.com/"
    assert inventory_rows[0]["first_seen"] == "2026-01-15T12:00:00+00:00"
    assert inventory_rows[0]["last_seen"] == "2026-02-10T12:00:00+00:00"

    report = render_html_report(database, run)
    assert "First seen" in report and "Last seen" in report
    assert "2025-12-31T12:00:00+00:00" in report

    # The flag is wired and the view distinguishes the two kinds of row.
    parser = build_parser()
    subparsers = [
        action for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    ][0]
    assert any(
        "--history" in action.option_strings
        for action in subparsers.choices["results"]._actions
    )

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        render_inventory_history(scan_history, scan_selected=True)
    rendered = buffer.getvalue()
    assert "FIRST SEEN" in rendered and "LAST SEEN" in rendered
    assert "ORIGIN" in rendered
    assert "returning" in rendered and " new " in rendered
    assert "graph-wide timestamps" in rendered

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        render_inventory_history(history, scan_selected=False)
    assert "ORIGIN" not in buffer.getvalue()

print("inventory history test passed")
