import sqlite3
import tempfile
from pathlib import Path
from sh4q.application.diff import build_scan_diff

with tempfile.TemporaryDirectory() as directory:
    path = str(Path(directory) / "diff.db")
    with sqlite3.connect(path) as db:
        db.executescript("CREATE TABLE nodes (id TEXT, type TEXT, value TEXT, attributes TEXT); CREATE TABLE relationships (id TEXT, from_id TEXT, to_id TEXT, type TEXT, attributes TEXT); CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT);")
        db.executemany("INSERT INTO nodes VALUES (?, ?, ?, '{}')", [("domain:a", "domain", "a"), ("domain:b", "domain", "b")])
        db.execute("INSERT INTO relationships VALUES (?, ?, ?, ?, '{}')", ("r1", "domain:a", "domain:b", "HAS_SUBDOMAIN"))
        db.executemany("INSERT INTO scan_assets VALUES (?, ?, ?, 'test')", [("old", "domain:a", "r1"), ("new", "domain:b", "r1")])
    result = build_scan_diff(path, "old", "new")
    assert result.added_assets == [{"type": "domain", "value": "b"}]
    assert result.removed_assets == [{"type": "domain", "value": "a"}]
print("scan diff test passed")
