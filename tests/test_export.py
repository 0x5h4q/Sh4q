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
        db.execute("CREATE TABLE relationships (id TEXT, from_id TEXT, to_id TEXT, type TEXT, attributes TEXT)")
        db.execute("CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT)")
        db.execute("CREATE TABLE evidence (scan_run_id TEXT)")
        db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)", ("domain:api.example.com", "domain", "api.example.com", '{"source":"test"}'))
        db.execute("INSERT INTO scan_assets VALUES (?, ?, ?, ?)", ("scan-1", "domain:api.example.com", "rel-1", "test"))
        db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)", ("url:https://api.example.com/", "url", "https://api.example.com/", "{}"))
        db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)", ("technology:nginx", "technology", "nginx", "{}"))
        db.execute("INSERT INTO relationships VALUES (?, ?, ?, ?, ?)", ("rel-tech", "url:https://api.example.com/", "technology:nginx", "DETECTED_TECHNOLOGY", '{"category":"web-server","version":"1.25","confidence":"explicit","status":200,"raw_observation":"header:server=nginx/1.25"}'))
        db.execute("INSERT INTO scan_assets VALUES (?, ?, ?, ?)", ("scan-1", "technology:nginx", "rel-tech", "native-http"))
    run = ScanRun("scan-1", "example.com", "start", "end", "COMPLETED")

    json_path = root / "report.json"
    assert export_scan(database, run, format="json", output=json_path) == 2
    document = json.loads(json_path.read_text())
    assert document["scan"]["id"] == "scan-1"
    domain = next(item for item in document["assets"] if item["type"] == "domain")
    assert domain["value"] == "api.example.com"
    assert domain["sources"] == ["test"]

    csv_path = root / "report.csv"
    assert export_scan(database, run, format="csv", output=csv_path) == 2
    with csv_path.open() as stream:
        rows = list(csv.DictReader(stream))
    assert rows[0]["scan_id"] == "scan-1"
    assert rows[0]["value"] == "api.example.com"

    technology_path = root / "technologies.csv"
    assert export_scan(database, run, format="csv", output=technology_path, asset_type="technology") == 1
    with technology_path.open() as stream:
        technology_rows = list(csv.DictReader(stream))
    assert technology_rows[0]["endpoint"] == "https://api.example.com/"
    assert technology_rows[0]["technology"] == "nginx"
    assert technology_rows[0]["confidence"] == "explicit"

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
