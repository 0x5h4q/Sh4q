import sqlite3
import tempfile
from pathlib import Path

from sh4q.application.html_report import render_html_report
from sh4q.storage.scan_runs import ScanRun


with tempfile.TemporaryDirectory() as directory:
    database = str(Path(directory) / "report.db")
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE nodes (id TEXT, type TEXT, value TEXT, attributes TEXT)")
        db.execute("CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT)")
        db.execute("CREATE TABLE relationships (id TEXT, from_id TEXT, to_id TEXT, type TEXT, attributes TEXT)")
        db.execute("CREATE TABLE evidence (id TEXT, target TEXT, plugin TEXT, kind TEXT, content TEXT, captured_at TEXT, scan_run_id TEXT)")
        db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)", (
            "url:1", "url", "https://api.example.com/?q=<script>", '{"status":200}'
        ))
        db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)", (
            "technology:next", "technology", "next.js", '{"category":"web-framework"}'
        ))
        db.executemany("INSERT INTO scan_assets VALUES (?, ?, ?, ?)", [
            ("scan-1", "url:1", "rel-url", "discovered-http"),
            ("scan-1", "technology:next", "rel-tech", "native"),
        ])
        db.execute("INSERT INTO relationships VALUES (?, ?, ?, ?, ?)", ("rel-tech", "url:1", "technology:next", "DETECTED_TECHNOLOGY", '{"status":200}'))
        db.executemany("INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?)", [
            ("e1", "example.com", "http", "http_error", '{"error":"timeout"}', "now", "scan-1"),
            ("e2", "example.com", "native", "request_metrics", '{"observed":{"admitted":2}}', "now", "scan-1"),
        ("e3", "example.com", "scheduler", "stage_metrics", '{"stages":[{"name":"dns","status":"completed","attempts":1,"discoveries":1,"duration_seconds":0.1}]}', "now", "scan-1"),
        ("e4", "example.com", "javascript-extraction", "javascript_endpoint_reference", '{"value":"https://example.com/api/me","source_endpoint":"https://example.com/"}', "now", "scan-1"),
        ])

    run = ScanRun("scan-1", "example.com", "start", "end", "COMPLETED")
    report = render_html_report(database, run)
    assert "<!doctype html>" in report
    assert "id=\"status\"" in report
    assert "id=\"technology\"" in report
    assert "api.example.com" in report
    assert "\\u003cscript>" in report
    assert "filtered.length" in report
    assert "Failures" in report
    assert "Stage timings" in report
    assert "Request metrics" in report
    assert "Evidence index" in report
    assert "JavaScript observations" in report
    assert "https://example.com/api/me" in report
    assert "not automatically requested" in report
    assert "HTTP status" in report
    assert "fetch(" not in report
    assert report.count("<select") == 5
    assert "Reset filters" in report
    assert "data:image/png;base64," in report
    assert 'alt="SH4Q"' in report
    assert "width: min(820px" in report
    assert "white-space: nowrap" in report
    assert "No assets match these filters" in report
print("HTML report test passed")
