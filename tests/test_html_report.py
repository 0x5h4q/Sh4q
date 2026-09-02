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

    run = ScanRun("scan-1", "example.com", "start", "end", "COMPLETED")
    report = render_html_report(database, run)
    assert "<!doctype html>" in report
    assert "id=\"status\"" in report
    assert "id=\"technology\"" in report
    assert "api.example.com" in report
    assert "\\u003cscript>" in report
    assert "filtered.length" in report
print("HTML report test passed")
