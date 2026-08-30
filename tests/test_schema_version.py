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
print("schema version test passed")
