import json
import sqlite3
import tempfile
from pathlib import Path

from sh4q.application.results import list_assets, list_failures


with tempfile.TemporaryDirectory() as directory:
    database = str(Path(directory) / "results.db")
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE nodes (id TEXT, type TEXT, value TEXT, attributes TEXT)")
        db.execute("CREATE TABLE relationships (from_id TEXT, to_id TEXT, type TEXT)")
        db.execute("CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT)")
        db.execute("CREATE TABLE evidence (target TEXT, plugin TEXT, kind TEXT, content TEXT, captured_at TEXT)")
        db.executemany("INSERT INTO nodes VALUES (?, ?, ?, ?)", [
            ("domain:api.example.com", "domain", "api.example.com", "{}"),
            ("domain:other.test", "domain", "other.test", "{}"),
            ("ip:93.184.216.34", "ip", "93.184.216.34", "{}"),
        ])
        db.execute(
            "INSERT INTO relationships VALUES (?, ?, ?)",
            ("domain:api.example.com", "ip:93.184.216.34", "RESOLVES_TO"),
        )
        db.execute(
            "INSERT INTO scan_assets VALUES (?, ?, ?, ?)",
            ("scan-1", "domain:api.example.com", "rel-1", "subfinder"),
        )
        db.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?)",
            ("example.com", "dns", "dns_error", json.dumps({"error": "failed"}), "2026-01-01"),
        )

    domains = list_assets(database, asset_type="domain", target="example.com")
    assert [row.value for row in domains] == ["api.example.com"]
    limited_domains = list_assets(database, asset_type="domain", target="example.com", limit=1)
    assert len(limited_domains) == 1
    ips = list_assets(database, asset_type="ip", target="example.com")
    assert [row.value for row in ips] == ["93.184.216.34"]
    scan_domains = list_assets(database, asset_type="domain", scan_id="scan-1")
    assert [row.value for row in scan_domains] == ["api.example.com"]
    failures = list_failures(database, target="example.com")
    assert failures[0][0:2] == ("dns", "dns_error")
print("results query test passed")
