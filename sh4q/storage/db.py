import sqlite3
import sys
from contextlib import asynccontextmanager, contextmanager

import aiosqlite

from .errors import StorageError


CURRENT_SCHEMA_VERSION = 4


class SchemaVersionError(Exception):
    pass


def _configure_sync(db: sqlite3.Connection) -> None:
    db.execute("PRAGMA busy_timeout=10000")
    db.execute("PRAGMA foreign_keys=ON")


def _table_exists(db: sqlite3.Connection, name: str) -> bool:
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone() is not None


def _columns_exist(db: sqlite3.Connection, table: str, columns: tuple[str, ...]) -> bool:
    available = {
        row[1] for row in db.execute(f"PRAGMA table_info({table})").fetchall()
    }
    return all(column in available for column in columns)


def row_identifier(db: sqlite3.Connection, table: str) -> str:
    """SQL expression for a row's identifier, tolerating narrow fixtures.

    Production tables have an `id` column. Older databases and test fixtures
    sometimes predate it; SQLite always provides `rowid`, so diagnostics can
    still name the row that failed to parse.
    """
    columns = {row[1] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}
    return "id" if "id" in columns else "rowid"


def node_timestamp_columns(
    db: sqlite3.Connection, prefix: str = "n"
) -> tuple[str, str]:
    """SQL expressions for a node's first/last seen timestamps.

    Databases created before these columns existed (and narrow test fixtures)
    must still be readable. Empty literals say the history was never recorded,
    which is true, and keep every result and export query working.
    """
    available = {
        row[1] for row in db.execute("PRAGMA table_info(nodes)").fetchall()
    }
    if {"first_seen", "last_seen"}.issubset(available):
        return f"{prefix}.first_seen", f"{prefix}.last_seen"
    return "''", "''"


def _migration_1(db: sqlite3.Connection) -> None:
    """Baseline migration for databases created before numbered migrations."""
    db.execute(
        "CREATE TABLE IF NOT EXISTS schema_metadata "
        "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )


def _migration_2(db: sqlite3.Connection) -> None:
    """Add indexes used by scan-owned queries when their tables are present."""
    if _table_exists(db, "evidence") and _columns_exist(
        db, "evidence", ("scan_run_id", "kind")
    ):
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_scan_kind "
            "ON evidence (scan_run_id, kind)"
        )
    if _table_exists(db, "scan_assets"):
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_assets_asset "
            "ON scan_assets (asset_id)"
        )
    if _table_exists(db, "scan_runs"):
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_started "
            "ON scan_runs (started_at DESC)"
        )


def _migration_3(db: sqlite3.Connection) -> None:
    """Add indexes for high-volume scan result and graph queries."""
    if _table_exists(db, "evidence") and _columns_exist(
        db, "evidence", ("scan_run_id", "kind", "captured_at", "target")
    ):
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_scan_kind_captured "
            "ON evidence (scan_run_id, kind, captured_at)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_target_captured "
            "ON evidence (target, captured_at)"
        )
    if _table_exists(db, "scan_assets") and _columns_exist(
        db, "scan_assets", ("scan_run_id", "source_plugin", "asset_id")
    ):
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_assets_scan_source_asset "
            "ON scan_assets (scan_run_id, source_plugin, asset_id)"
        )
    if _table_exists(db, "relationships") and _columns_exist(
        db, "relationships", ("from_id", "to_id")
    ):
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_relationships_from "
            "ON relationships (from_id)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_relationships_to "
            "ON relationships (to_id)"
        )


def _migration_4(db: sqlite3.Connection) -> None:
    """Add indexes for event recovery and ordered node inventory queries."""
    if _table_exists(db, "event_log") and _columns_exist(
        db, "event_log", ("status", "next_attempt_at", "created_at")
    ):
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_event_log_status_next "
            "ON event_log (status, next_attempt_at, created_at)"
        )
    if _table_exists(db, "nodes") and _columns_exist(db, "nodes", ("type", "value")):
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_nodes_type_value "
            "ON nodes (type, value)"
        )


MIGRATIONS = {1: _migration_1, 2: _migration_2, 3: _migration_3, 4: _migration_4}


@contextmanager
def open_sync_database(path: str, operation: str = "database operation"):
    """Open a synchronous connection, translating sqlite errors.

    Every SQL statement inside the `with` block is covered: sqlite raises from
    the statement, the exception leaves the block, and this wrapper names the
    database and the operation before re-raising it as `StorageError`.
    """
    try:
        db = sqlite3.connect(path, timeout=10)
    except sqlite3.Error as error:
        raise StorageError(
            f"cannot open database {path}: {error}",
            database=path,
            operation="open",
        ) from error
    try:
        _configure_sync(db)
        yield db
    except sqlite3.Error as error:
        raise StorageError(
            f"{operation} failed on {path}: {error}",
            database=path,
            operation=operation,
        ) from error
    finally:
        # Do not let a close failure replace the error that caused the close.
        active_error = sys.exc_info()[0] is not None
        try:
            db.close()
        except sqlite3.Error as error:
            if not active_error:
                raise StorageError(
                    f"closing {path} failed: {error}",
                    database=path,
                    operation="close",
                ) from error


def ensure_schema_version(path: str) -> int:
    with open_sync_database(path, "initialize schema") as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("BEGIN IMMEDIATE")
        _migration_1(db)
        row = db.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
        native_version = int(db.execute("PRAGMA user_version").fetchone()[0])
        version = (
            int(row[0])
            if row is not None
            else min(native_version, CURRENT_SCHEMA_VERSION)
        )
        if version > CURRENT_SCHEMA_VERSION:
            db.rollback()
            raise SchemaVersionError(
                f"database schema version {version} is newer than supported version {CURRENT_SCHEMA_VERSION}"
            )
        for migration_version in range(version + 1, CURRENT_SCHEMA_VERSION + 1):
            MIGRATIONS[migration_version](db)
        db.execute(
            "INSERT INTO schema_metadata (key, value) VALUES ('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(CURRENT_SCHEMA_VERSION),),
        )
        db.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")
        db.commit()
        return CURRENT_SCHEMA_VERSION


@asynccontextmanager
async def open_database(path: str, operation: str = "database operation"):
    """Open an async connection, translating sqlite errors.

    The same contract as `open_sync_database`: every awaited statement runs
    inside the translated block, so callers receive `StorageError` rather than
    an aiosqlite traceback.
    """
    try:
        db = await aiosqlite.connect(path, timeout=10)
    except sqlite3.Error as error:
        raise StorageError(
            f"cannot open database {path}: {error}",
            database=path,
            operation="open",
        ) from error
    try:
        await db.execute("PRAGMA busy_timeout=10000")
        await db.execute("PRAGMA foreign_keys=ON")
        yield db
    except sqlite3.Error as error:
        raise StorageError(
            f"{operation} failed on {path}: {error}",
            database=path,
            operation=operation,
        ) from error
    finally:
        active_error = sys.exc_info()[0] is not None
        try:
            await db.close()
        except sqlite3.Error as error:
            if not active_error:
                raise StorageError(
                    f"closing {path} failed: {error}",
                    database=path,
                    operation="close",
                ) from error
