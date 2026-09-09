import sqlite3
from contextlib import asynccontextmanager, contextmanager

import aiosqlite


CURRENT_SCHEMA_VERSION = 3


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


MIGRATIONS = {1: _migration_1, 2: _migration_2, 3: _migration_3}


@contextmanager
def open_sync_database(path: str):
    db = sqlite3.connect(path, timeout=10)
    try:
        _configure_sync(db)
        yield db
    finally:
        db.close()


def ensure_schema_version(path: str) -> int:
    with open_sync_database(path) as db:
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
async def open_database(path: str):
    db = await aiosqlite.connect(path, timeout=10)
    try:
        await db.execute("PRAGMA busy_timeout=10000")
        await db.execute("PRAGMA foreign_keys=ON")
        yield db
    finally:
        await db.close()
