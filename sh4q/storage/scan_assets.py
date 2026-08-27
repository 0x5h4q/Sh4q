from sh4q.storage.db import open_database


class SQLiteScanAssetStore:
    def __init__(self, database: str):
        self._database = database

    async def init(self) -> None:
        async with open_database(self._database) as db:
            await db.execute(
                """CREATE TABLE IF NOT EXISTS scan_assets (
                scan_run_id TEXT NOT NULL, asset_id TEXT NOT NULL,
                relationship_id TEXT NOT NULL, source_plugin TEXT NOT NULL,
                PRIMARY KEY (scan_run_id, relationship_id))"""
            )
            await db.commit()

    async def record(self, scan_run_id, asset_id, relationship_id, source_plugin) -> None:
        if not scan_run_id:
            return
        async with open_database(self._database) as db:
            await db.execute(
                "INSERT OR IGNORE INTO scan_assets VALUES (?, ?, ?, ?)",
                (scan_run_id, asset_id, relationship_id, source_plugin),
            )
            await db.commit()
