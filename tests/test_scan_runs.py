import tempfile
from pathlib import Path

import sqlite3

from sh4q.storage.scan_runs import create_scan, finish_scan, latest_scan, list_scans, scan_asset_count

with tempfile.TemporaryDirectory() as directory:
    database = str(Path(directory) / "runs.db")
    run = create_scan(database, "example.com")
    assert run.status == "RUNNING"
    finish_scan(database, run.id, "COMPLETED")
    saved = list_scans(database)[0]
    assert saved.id == run.id
    assert saved.status == "COMPLETED"
    assert latest_scan(database).id == run.id
    assert latest_scan(database, "example.com").id == run.id
    unfinished = create_scan(database, "example.com")
    assert latest_scan(database).id == run.id
    assert latest_scan(database, completed_only=False).id == unfinished.id
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT)")
        db.executemany("INSERT INTO scan_assets VALUES (?, ?, ?, ?)", [(run.id, "asset-1", "rel-1", "dns"), (run.id, "asset-1", "rel-2", "http"), (run.id, "asset-2", "rel-3", "dns")])
    assert scan_asset_count(database, run.id) == 2
print("scan runs test passed")
