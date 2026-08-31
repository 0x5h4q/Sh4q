import json
import sqlite3
import tempfile
from pathlib import Path

from sh4q.application.results import list_assets, list_failures, list_technology_observations


with tempfile.TemporaryDirectory() as directory:
    database = str(Path(directory) / "results.db")
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE nodes (id TEXT, type TEXT, value TEXT, attributes TEXT)")
        db.execute("CREATE TABLE relationships (id TEXT, from_id TEXT, to_id TEXT, type TEXT, attributes TEXT)")
        db.execute("CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT)")
        db.execute("CREATE TABLE evidence (target TEXT, plugin TEXT, kind TEXT, content TEXT, captured_at TEXT, scan_run_id TEXT)")
        db.executemany("INSERT INTO nodes VALUES (?, ?, ?, ?)", [
            ("domain:api.example.com", "domain", "api.example.com", "{}"),
            ("domain:other.test", "domain", "other.test", "{}"),
            ("ip:93.184.216.34", "ip", "93.184.216.34", "{}"),
            ("url:https://api.example.com/", "url", "https://api.example.com/", "{}"),
            ("technology:nginx", "technology", "nginx", "{\"observed_name\":\"nginx\"}"),
        ])
        db.execute(
            "INSERT INTO relationships VALUES (?, ?, ?, ?, ?)",
            ("rel-dns", "domain:api.example.com", "ip:93.184.216.34", "RESOLVES_TO", "{}"),
        )
        db.execute(
            "INSERT INTO relationships VALUES (?, ?, ?, ?, ?)",
            ("rel-tech", "url:https://api.example.com/", "technology:nginx", "DETECTED_TECHNOLOGY", '{"category":"web-server","confidence":"explicit","status":200,"raw_observation":"header:server=nginx"}'),
        )
        db.execute(
            "INSERT INTO scan_assets VALUES (?, ?, ?, ?)",
            ("scan-1", "domain:api.example.com", "rel-1", "subfinder"),
        )
        db.execute(
            "INSERT INTO scan_assets VALUES (?, ?, ?, ?)",
            ("scan-1", "technology:nginx", "rel-tech", "httpx-fingerprint"),
        )
        db.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?)",
            ("example.com", "dns", "dns_error", json.dumps({"error": "failed"}), "2026-01-01", "scan-old"),
        )
        db.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?)",
            ("example.com", "http", "http_error", json.dumps({"error": "latest"}), "2026-01-02", "scan-1"),
        )

    domains = list_assets(database, asset_type="domain", target="example.com")
    assert [row.value for row in domains] == ["api.example.com"]
    limited_domains = list_assets(database, asset_type="domain", target="example.com", limit=1)
    assert len(limited_domains) == 1
    ips = list_assets(database, asset_type="ip", target="example.com")
    assert [row.value for row in ips] == ["93.184.216.34"]
    scan_domains = list_assets(database, asset_type="domain", scan_id="scan-1")
    assert [row.value for row in scan_domains] == ["api.example.com"]
    technologies = list_assets(database, asset_type="technology", target="example.com")
    assert [row.value for row in technologies] == ["nginx"]
    scan_technologies = list_assets(database, asset_type="technology", scan_id="scan-1")
    assert [row.value for row in scan_technologies] == ["nginx"]
    observations = list_technology_observations(database, scan_id="scan-1")
    assert observations[0].endpoint == "https://api.example.com/"
    assert observations[0].signal == "header:server=nginx"
    failures = list_failures(database, target="example.com")
    assert failures[0][0:2] == ("http", "http_error")
    scan_failures = list_failures(database, target="example.com", scan_id="scan-1")
    assert [row[0:2] for row in scan_failures] == [("http", "http_error")]
print("results query test passed")
