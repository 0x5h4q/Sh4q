from contextlib import asynccontextmanager

import aiosqlite


@asynccontextmanager
async def open_database(path: str):
    db = await aiosqlite.connect(path, timeout=10)
    try:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA busy_timeout=10000")
        await db.execute("PRAGMA foreign_keys=ON")
        yield db
    finally:
        await db.close()
