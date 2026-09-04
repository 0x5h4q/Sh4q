from __future__ import annotations

from dataclasses import dataclass
from sh4q.storage.db import open_sync_database


@dataclass(frozen=True)
class ScanDiff:
    before: str
    after: str
    added_assets: list[dict]
    removed_assets: list[dict]
    added_relationships: list[dict]
    removed_relationships: list[dict]


def _assets(db, scan_id):
    return { (row[0], row[1]): {"type": row[0], "value": row[1]} for row in db.execute(
        "SELECT DISTINCT n.type, n.value FROM scan_assets sa JOIN nodes n ON n.id = sa.asset_id WHERE sa.scan_run_id = ?", (scan_id,)
    ) }


def _relationships(db, scan_id):
    return {(row[0], row[1], row[2]): {"from": row[0], "type": row[1], "to": row[2]} for row in db.execute(
        """SELECT DISTINCT r.from_id, r.type, r.to_id FROM scan_assets sa
        JOIN relationships r ON r.id = sa.relationship_id WHERE sa.scan_run_id = ?""", (scan_id,)
    )}


def build_scan_diff(database: str, before: str, after: str) -> ScanDiff:
    with open_sync_database(database) as db:
        old_assets, new_assets = _assets(db, before), _assets(db, after)
        old_relationships, new_relationships = _relationships(db, before), _relationships(db, after)
    return ScanDiff(
        before=before, after=after,
        added_assets=sorted((new_assets[key] for key in new_assets.keys() - old_assets.keys()), key=lambda item: (item["type"], item["value"])),
        removed_assets=sorted((old_assets[key] for key in old_assets.keys() - new_assets.keys()), key=lambda item: (item["type"], item["value"])),
        added_relationships=sorted((new_relationships[key] for key in new_relationships.keys() - old_relationships.keys()), key=lambda item: (item["from"], item["type"], item["to"])),
        removed_relationships=sorted((old_relationships[key] for key in old_relationships.keys() - new_relationships.keys()), key=lambda item: (item["from"], item["type"], item["to"])),
    )


def diff_document(result: ScanDiff) -> dict:
    return {
        "before": result.before,
        "after": result.after,
        "added_assets": result.added_assets,
        "removed_assets": result.removed_assets,
        "added_relationships": result.added_relationships,
        "removed_relationships": result.removed_relationships,
    }
