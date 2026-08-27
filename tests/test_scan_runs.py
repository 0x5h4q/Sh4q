import tempfile
from pathlib import Path

from sh4q.storage.scan_runs import create_scan, finish_scan, list_scans

with tempfile.TemporaryDirectory() as directory:
    database = str(Path(directory) / "runs.db")
    run = create_scan(database, "example.com")
    assert run.status == "RUNNING"
    finish_scan(database, run.id, "COMPLETED")
    saved = list_scans(database)[0]
    assert saved.id == run.id
    assert saved.status == "COMPLETED"
print("scan runs test passed")
