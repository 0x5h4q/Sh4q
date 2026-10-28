"""Storage hardening: corrupt rows and database failures are reported, not fatal.

The old read paths called `json.loads` on every stored field and let sqlite
errors escape as tracebacks. These checks use deliberately broken rows and a
database path that cannot be opened, so no network or live data is involved.
"""

import asyncio
import contextlib
import io
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

from sh4q.application.exporter import export_scan
from sh4q.application.results import (
    list_assets,
    list_failures,
    list_javascript_observations,
    summarize_names,
)
from sh4q.application.scan_report import build_scan_report
from sh4q.events.event_log import DurableEventLog
from sh4q.storage.db import open_database, open_sync_database
from sh4q.storage.errors import CorruptRecordError, StorageError
from sh4q.storage.json_fields import MALFORMED, decode_object
from sh4q.storage.scan_runs import ScanRun


def test_decode_helper() -> None:
    assert decode_object('{"a": 1}', field="attributes") == {"a": 1}

    skipped: list[CorruptRecordError] = []
    assert (
        decode_object("{", field="attributes", record_id="row-1", skipped=skipped)
        is MALFORMED
    )
    assert len(skipped) == 1
    assert skipped[0].record_id == "row-1"
    assert skipped[0].field == "attributes"
    assert "row-1" in str(skipped[0])

    try:
        decode_object("{", field="attributes", record_id="row-2")
    except CorruptRecordError as error:
        assert error.record_id == "row-2"
    else:
        raise AssertionError("a malformed field should raise without a collector")

    # Valid JSON of the wrong shape is corruption too: callers immediately
    # call .get() on these values.
    skipped.clear()
    assert (
        decode_object("[]", field="content", record_id="row-3", skipped=skipped)
        is MALFORMED
    )
    assert "expected an object" in str(skipped[0])


def test_storage_error_translation() -> None:
    with tempfile.TemporaryDirectory(prefix="sh4q_storage_") as directory:
        try:
            with open_sync_database(directory):
                pass
        except StorageError as error:
            assert error.database == directory
            assert error.operation == "open"
            assert directory in str(error)
        else:
            raise AssertionError("opening a directory as a database should fail")

        database = os.path.join(directory, "broken.db")
        try:
            with open_sync_database(database, "test query") as db:
                db.execute("SELECT * FROM table_that_does_not_exist").fetchall()
        except StorageError as error:
            assert error.database == database
            assert error.operation == "test query"
            assert "no such table" in str(error)
        else:
            raise AssertionError("a failed statement should become StorageError")


def _seed_read_database(path: str) -> None:
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE nodes (id TEXT, type TEXT, value TEXT, attributes TEXT, "
            "first_seen TEXT, last_seen TEXT)"
        )
        db.executemany(
            "INSERT INTO nodes VALUES (?, 'domain', ?, ?, '', '')",
            [
                ("node-good", "good.example", '{"status": 200}'),
                ("node-bad", "bad.example", "{"),
            ],
        )
        db.execute(
            "CREATE TABLE evidence (target TEXT, plugin TEXT, kind TEXT, "
            "content TEXT, captured_at TEXT, scan_run_id TEXT)"
        )
        db.executemany(
            "INSERT INTO evidence VALUES ('example.com', ?, ?, ?, 'now', 'scan-1')",
            [
                ("adapter", "adapter_execution", '{"returncode": 1}'),
                ("adapter", "adapter_execution", "{"),
                ("js", "javascript_url", '{"value": "https://example.com/a.js", '
                                          '"source_endpoint": "https://example.com/"}'),
                ("js", "javascript_url", "{"),
                ("native", "dns_resolution", '{"domain": "good.example"}'),
                ("native", "dns_resolution", "{"),
            ],
        )


def test_reads_skip_corrupt_rows() -> None:
    with tempfile.TemporaryDirectory(prefix="sh4q_storage_") as directory:
        database = os.path.join(directory, "reads.db")
        _seed_read_database(database)

        skipped: list[CorruptRecordError] = []
        assets = list_assets(database, limit=None, skipped=skipped)
        assert [asset.value for asset in assets] == ["good.example"]
        assert [issue.record_id for issue in skipped] == ["node-bad"]

        skipped.clear()
        failures = list_failures(database, limit=None, skipped=skipped)
        assert len(failures) == 1
        assert skipped and skipped[0].field == "content"

        skipped.clear()
        observations = list_javascript_observations(database, limit=None, skipped=skipped)
        assert [item.value for item in observations] == ["https://example.com/a.js"]
        assert len(skipped) == 1

        skipped.clear()
        names = summarize_names(database, skipped=skipped)
        assert names.resolved >= 1
        assert len(skipped) == 1

        # Without a collector, the same row raises a named error rather than a
        # bare JSONDecodeError.
        try:
            list_assets(database, limit=None)
        except CorruptRecordError as error:
            assert error.record_id == "node-bad"
        else:
            raise AssertionError("list_assets should raise without a collector")


def _seed_export_database(path: str) -> None:
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE nodes (id TEXT, type TEXT, value TEXT, attributes TEXT, "
            "first_seen TEXT, last_seen TEXT)"
        )
        db.executemany(
            "INSERT INTO nodes VALUES (?, 'domain', ?, ?, '2026-01-01', '2026-01-01')",
            [
                ("node-good", "good.example", '{"status": 200}'),
                ("node-bad", "bad.example", "{"),
            ],
        )
        db.execute(
            "CREATE TABLE relationships (id TEXT, from_id TEXT, to_id TEXT, "
            "type TEXT, attributes TEXT, created_at TEXT)"
        )
        db.execute(
            "CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, "
            "relationship_id TEXT, source_plugin TEXT)"
        )
        db.executemany(
            "INSERT INTO scan_assets VALUES ('scan-1', ?, NULL, 'http')",
            [("node-good",), ("node-bad",)],
        )
        db.execute(
            "CREATE TABLE evidence (id TEXT, scan_run_id TEXT, target TEXT, "
            "plugin TEXT, kind TEXT, content TEXT, captured_at TEXT)"
        )
        db.execute(
            "INSERT INTO evidence VALUES ('ev-bad', 'scan-1', 'example.com', "
            "'native', 'request_metrics', '{', 'now')"
        )


def test_export_and_report_skip_and_count() -> None:
    with tempfile.TemporaryDirectory(prefix="sh4q_storage_") as directory:
        database = os.path.join(directory, "export.db")
        _seed_export_database(database)
        run = ScanRun("scan-1", "example.com", "start", "end", "COMPLETED")

        output = Path(directory) / "export.json"
        result = export_scan(database, run, format="json", output=output)
        assert int(result) == 1
        assert result.skipped_records == 1
        assert result.skipped_examples == ("bad.example",)
        assert "Skipped 1 malformed record(s)" in result.skipped_summary
        document = json.loads(output.read_text(encoding="utf-8"))
        assert [asset["value"] for asset in document["assets"]] == ["good.example"]

        report = build_scan_report(database, run)
        assert report.skipped_records == 1


def test_event_recovery_dead_letters_corrupt_payload() -> None:
    async def scenario(database: str) -> None:
        log = DurableEventLog(database)
        await log.init()
        async with open_database(database, "seed events") as db:
            await db.executemany(
                "INSERT INTO event_log (id, type, payload, status, created_at, "
                "updated_at, error, attempts, next_attempt_at) "
                "VALUES (?, 'discovery', ?, 'PENDING', 'now', 'now', NULL, 0, NULL)",
                [
                    ("good", json.dumps({"scan_target": "example.com", "kind": "url"})),
                    ("bad", "{"),
                ],
            )
            await db.commit()

        recovered = await log.recover_unfinished()
        assert [event.id for event in recovered] == ["good"]

        async with open_database(database, "check events") as db:
            rows = await (
                await db.execute("SELECT id, status, error FROM event_log ORDER BY id")
            ).fetchall()
        statuses = {row[0]: row[1] for row in rows}
        assert statuses["good"] == "PENDING"
        assert statuses["bad"] == "DEAD_LETTER"

        records = await log.list_records(limit=None)
        assert [record.id for record in records] == ["good"]
        assert len(log.skipped) == 1

        # The summary reads payload fields in SQL. A corrupt payload must not
        # make json_extract fail; it is grouped with empty metadata instead.
        groups = await log.summarize(limit=None)
        assert sum(group.count for group in groups) == 2

    with tempfile.TemporaryDirectory(prefix="sh4q_storage_") as directory:
        asyncio.run(scenario(os.path.join(directory, "events.db")))


def test_cli_renders_storage_error() -> None:
    from sh4q.cli.main import main

    with tempfile.TemporaryDirectory(prefix="sh4q_storage_") as directory:
        old_argv = sys.argv
        sys.argv = ["sh4q", "results", "--database", directory]
        stderr = io.StringIO()
        try:
            with contextlib.redirect_stderr(stderr):
                try:
                    main()
                except SystemExit as exit:
                    assert exit.code == 2
                else:
                    raise AssertionError("an unreadable database should exit nonzero")
        finally:
            sys.argv = old_argv

    message = stderr.getvalue()
    assert "Traceback" not in message
    assert directory in message
    assert "database" in message.lower()


def main() -> None:
    test_decode_helper()
    test_storage_error_translation()
    test_reads_skip_corrupt_rows()
    test_export_and_report_skip_and_count()
    test_event_recovery_dead_letters_corrupt_payload()
    test_cli_renders_storage_error()
    print("storage hardening test passed")


if __name__ == "__main__":
    main()
