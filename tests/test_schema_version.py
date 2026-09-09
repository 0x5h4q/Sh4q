import tempfile
from pathlib import Path

from sh4q.storage.db import (
    CURRENT_SCHEMA_VERSION,
    SchemaVersionError,
    ensure_schema_version,
    open_sync_database,
)


with tempfile.TemporaryDirectory() as directory:
    database = str(Path(directory) / "schema.db")
    assert ensure_schema_version(database) == CURRENT_SCHEMA_VERSION
    assert ensure_schema_version(database) == CURRENT_SCHEMA_VERSION
    with open_sync_database(database) as db:
        assert db.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert db.execute("PRAGMA busy_timeout").fetchone()[0] == 10000
        assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert db.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION
        db.execute(
            "UPDATE schema_metadata SET value = ? WHERE key = 'schema_version'",
            (str(CURRENT_SCHEMA_VERSION + 1),),
        )
        db.commit()
    try:
        ensure_schema_version(database)
    except SchemaVersionError as error:
        assert "newer than supported" in str(error)
    else:
        raise AssertionError("newer schema was accepted")

    # Older numbered schemas are upgraded transactionally and remain usable.
    with open_sync_database(database) as db:
        db.execute(
            "UPDATE schema_metadata SET value = '1' WHERE key = 'schema_version'"
        )
        db.execute("PRAGMA user_version = 1")
        db.commit()
    assert ensure_schema_version(database) == CURRENT_SCHEMA_VERSION
    with open_sync_database(database) as db:
        assert db.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()[0] == str(CURRENT_SCHEMA_VERSION)

    indexed_database = str(Path(directory) / "indexed.db")
    with open_sync_database(indexed_database) as db:
        db.executescript(
            "CREATE TABLE evidence (scan_run_id TEXT, kind TEXT, captured_at TEXT, target TEXT);"
            "CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, source_plugin TEXT);"
            "CREATE TABLE scan_runs (started_at TEXT);"
            "CREATE TABLE relationships (from_id TEXT, to_id TEXT);"
            "CREATE TABLE nodes (type TEXT, value TEXT);"
            "CREATE TABLE event_log (status TEXT, next_attempt_at TEXT, created_at TEXT);"
        )
        db.commit()
    assert ensure_schema_version(indexed_database) == CURRENT_SCHEMA_VERSION
    with open_sync_database(indexed_database) as db:
        indexes = {
            row[1]
            for row in db.execute(
                "SELECT type, name FROM sqlite_master WHERE type = 'index'"
            ).fetchall()
        }
    assert "idx_evidence_scan_kind" in indexes
    assert "idx_scan_assets_asset" in indexes
    assert "idx_scan_runs_started" in indexes
    assert "idx_evidence_scan_kind_captured" in indexes
    assert "idx_evidence_target_captured" in indexes
    assert "idx_scan_assets_scan_source_asset" in indexes
    assert "idx_relationships_from" in indexes
    assert "idx_relationships_to" in indexes
    assert "idx_nodes_type_value" in indexes
    assert "idx_event_log_status_next" in indexes
print("schema version test passed")
