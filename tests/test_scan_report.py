import json
import sqlite3
import tempfile
from pathlib import Path

from sh4q.application.scan_report import build_scan_report
from sh4q.storage.scan_runs import ScanRun


with tempfile.TemporaryDirectory() as directory:
    database = str(Path(directory) / "report.db")
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE nodes (id TEXT, type TEXT, value TEXT, attributes TEXT)")
        db.execute("CREATE TABLE relationships (id TEXT, from_id TEXT, to_id TEXT, type TEXT, attributes TEXT)")
        db.execute("CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT)")
        db.execute("CREATE TABLE evidence (scan_run_id TEXT, kind TEXT, content TEXT)")
        db.executemany("INSERT INTO nodes VALUES (?, ?, ?, ?)", [
            ("domain:api.example.com", "domain", "api.example.com", "{}"),
            ("ip:93.184.216.34", "ip", "93.184.216.34", "{}"),
            ("url:https://api.example.com/", "url", "https://api.example.com/", "{}"),
            ("technology:nginx", "technology", "nginx", "{}"),
        ])
        db.executemany("INSERT INTO relationships VALUES (?, ?, ?, ?, ?)", [
            ("dns-rel", "domain:api.example.com", "ip:93.184.216.34", "RESOLVES_TO", "{}"),
            ("http-rel", "domain:api.example.com", "url:https://api.example.com/", "SERVES", "{}"),
            ("tech-rel", "url:https://api.example.com/", "technology:nginx", "DETECTED_TECHNOLOGY", "{}"),
        ])
        db.executemany("INSERT INTO scan_assets VALUES (?, ?, ?, ?)", [
            ("scan-1", "ip:93.184.216.34", "dns-rel", "dns"),
            ("scan-1", "url:https://api.example.com/", "http-rel", "http"),
            ("scan-1", "technology:nginx", "tech-rel", "native-http"),
        ])
        db.executemany("INSERT INTO evidence VALUES (?, ?, ?)", [
            ("scan-1", "discovered_dns_error", json.dumps({"reason": "nxdomain"})),
            ("scan-1", "http_error", json.dumps({"error": "timeout"})),
            ("scan-1", "request_metrics", json.dumps({"observed": {"admitted": 2}})),
            ("scan-1", "stage_metrics", json.dumps({"stages": [{"name": "dns", "status": "completed", "attempts": 1, "discoveries": 1, "duration_seconds": 0.5}]})),
        ])

    run = ScanRun("scan-1", "example.com", "start", "end", "COMPLETED")
    report = build_scan_report(database, run)
    assert report.dns_hostnames == 1
    assert report.http_endpoints == 1
    assert report.technology_assets == 1
    assert report.technology_observations == 1
    assert report.dns_failures == {"nxdomain": 1}
    assert report.http_failures == 1
    assert report.request_metrics["observed"]["admitted"] == 2
    assert report.stages[0]["name"] == "dns"
print("scan report test passed")
