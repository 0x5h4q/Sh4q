import tempfile
from pathlib import Path

import sqlite3

from sh4q.storage.scan_runs import count_scans, create_scan, finish_scan, latest_scan, list_scans, scan_asset_count

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

    # --- the listing says how many runs it is showing -----------------------
    # `scans` printed no count line at all, and list_scans clamped a requested
    # limit to 500 silently.
    total = count_scans(database)
    assert total == len(list_scans(database, limit=None)), total
    assert total >= 2, total
    assert len(list_scans(database, limit=1)) == 1
    assert len(list_scans(database, limit=total + 100)) == total, (
        "a limit above the run count must return every run"
    )
print("scan runs test passed")


# --- a count over an untouched database --------------------------------------
# `scans` creates the table when it is missing, so the count has to as well
# rather than raising on a database that has never recorded a run.
import tempfile  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

with tempfile.TemporaryDirectory() as _directory:
    _fresh = str(_Path(_directory) / "fresh.db")
    sqlite3.connect(_fresh).close()
    assert count_scans(_fresh) == 0
    assert list_scans(_fresh) == []


# --- the event coverage line counts the groups shown, not the whole log ------
# "Those groups cover 7179 event(s)" printed beneath "Showing 5 of 18 event
# group(s)" reported the size of the whole log, not of the five shown groups.
from dataclasses import dataclass  # noqa: E402

from sh4q.cli.main import event_coverage  # noqa: E402


@dataclass
class _Group:
    count: int


assert event_coverage([_Group(742), _Group(714), _Group(6), _Group(1032), _Group(2086)], 7179) == (
    "Those groups cover 4580 of 7179 event(s) in the log."
)
assert event_coverage([_Group(7179)], 7179) == (
    "Those groups cover all 7179 event(s) in the log."
)
assert event_coverage([], 0) == "Those groups cover all 0 event(s) in the log."
print("scan run and event coverage counting test passed")
