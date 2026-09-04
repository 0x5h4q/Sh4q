import json
import sqlite3
import tempfile
from pathlib import Path

from sh4q.application.exporter import export_scan
from sh4q.application.redaction import redact_url
from sh4q.storage.scan_runs import ScanRun

assert redact_url("https://example.com/path?view=full&token=abc#frag") == "https://example.com/path?view=full&token=%5BREDACTED%5D"
assert redact_url("https://example.com/path") == "https://example.com/path"

with tempfile.TemporaryDirectory() as directory:
    database = str(Path(directory) / "redact.db")
    with sqlite3.connect(database) as db:
        db.executescript("CREATE TABLE nodes (id TEXT, type TEXT, value TEXT, attributes TEXT); CREATE TABLE relationships (id TEXT, from_id TEXT, to_id TEXT, type TEXT, attributes TEXT); CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT); CREATE TABLE evidence (scan_run_id TEXT);")
        db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)", ("url:https://example.com/path?token=abc", "url", "https://example.com/path?token=abc", "{}"))
        db.execute("INSERT INTO scan_assets VALUES (?, ?, ?, ?)", ("scan", "url:https://example.com/path?token=abc", "rel", "test"))
    output = Path(directory) / "report.json"
    export_scan(database, ScanRun("scan", "example.com", "start", "end", "COMPLETED"), format="json", output=output, redact=True)
    document = json.loads(output.read_text())
    assert "REDACTED" in document["assets"][0]["value"]
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT value FROM nodes").fetchone()[0].endswith("token=abc")
print("export redaction test passed")
