import sqlite3
from contextlib import asynccontextmanager, contextmanager

import aiosqlite


CURRENT_SCHEMA_VERSION = 1


class SchemaVersionError(Exception):
    pass


def _configure_sync(db: sqlite3.Connection) -> None:
    db.execute("PRAGMA busy_timeout=10000")
    db.execute("PRAGMA foreign_keys=ON")


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
        db.execute(
            "CREATE TABLE IF NOT EXISTS schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        row = db.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
        if row is None:
            db.execute(
                "INSERT INTO schema_metadata (key, value) VALUES ('schema_version', ?)",
                (str(CURRENT_SCHEMA_VERSION),),
            )
            db.commit()
            return CURRENT_SCHEMA_VERSION
        version = int(row[0])
        if version > CURRENT_SCHEMA_VERSION:
            raise SchemaVersionError(
                f"database schema version {version} is newer than supported version {CURRENT_SCHEMA_VERSION}"
            )
        if version < CURRENT_SCHEMA_VERSION:
            raise SchemaVersionError(
                f"database schema version {version} requires migration to version {CURRENT_SCHEMA_VERSION}"
            )
        return version


@asynccontextmanager
async def open_database(path: str):
    db = await aiosqlite.connect(path, timeout=10)
    try:
        await db.execute("PRAGMA busy_timeout=10000")
        await db.execute("PRAGMA foreign_keys=ON")
        yield db
    finally:
        await db.close()
