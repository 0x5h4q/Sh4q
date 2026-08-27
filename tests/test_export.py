import csv
import json
import sqlite3
import tempfile
from pathlib import Path

from sh4q.application.exporter import ScanOwnershipUnavailableError, export_scan
from sh4q.storage.scan_runs import ScanRun


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    database = str(root / "export.db")
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE nodes (id TEXT, type TEXT, value TEXT, attributes TEXT)")
        db.execute("CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT)")
        db.execute("CREATE TABLE evidence (scan_run_id TEXT)")
        db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)", ("domain:api.example.com", "domain", "api.example.com", '{"source":"test"}'))
        db.execute("INSERT INTO scan_assets VALUES (?, ?, ?, ?)", ("scan-1", "domain:api.example.com", "rel-1", "test"))
    run = ScanRun("scan-1", "example.com", "start", "end", "COMPLETED")

    json_path = root / "report.json"
    assert export_scan(database, run, format="json", output=json_path) == 1
    document = json.loads(json_path.read_text())
    assert document["scan"]["id"] == "scan-1"
    assert document["assets"][0]["value"] == "api.example.com"
    assert document["assets"][0]["sources"] == ["test"]

    csv_path = root / "report.csv"
    assert export_scan(database, run, format="csv", output=csv_path) == 1
    with csv_path.open() as stream:
        rows = list(csv.DictReader(stream))
    assert rows[0]["scan_id"] == "scan-1"
    assert rows[0]["value"] == "api.example.com"

    try:
        export_scan(database, run, format="json", output=json_path)
    except FileExistsError:
        pass
    else:
        raise AssertionError("existing export was overwritten without --force")

    with sqlite3.connect(database) as db:
        db.execute("INSERT INTO evidence VALUES (?)", ("old-scan",))
    old_run = ScanRun("old-scan", "example.com", "start", "end", "COMPLETED")
    try:
        export_scan(database, old_run, format="json", output=root / "old.json")
    except ScanOwnershipUnavailableError:
        pass
    else:
        raise AssertionError("migration-era scan was exported as a genuine empty scan")
print("scan export test passed")
