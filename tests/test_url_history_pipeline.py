import asyncio
import contextlib
import io
import json
import sqlite3
import tempfile
from pathlib import Path

from sh4q.application.exporter import export_scan
from sh4q.application.scan_report import build_scan_report
from sh4q.config import Sh4qConfig
from sh4q.events import Event
from sh4q.handlers import make_discovery_handler
from sh4q.scope import ScopeEngine
from sh4q.storage.scan_runs import ScanRun


class Storage:
    def __init__(self):
        self.nodes = {}
        self.relationships = {}

    async def save_node(self, node):
        self.nodes[node.id] = node

    async def save_relationship(self, relationship):
        self.relationships[relationship.id] = relationship


class Evidence:
    def __init__(self):
        self.records = []

    async def append(self, evidence):
        self.records.append(evidence)


async def handler_check():
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    storage, evidence, stats = Storage(), Evidence(), {}
    handler = make_discovery_handler(scope, storage, evidence, stats=stats)
    event = {"kind": "url_history_found", "source_plugin": "url-history", "scan_target": "example.com",
             "data": {"url": "https://API.Example.com/path?q=Mixed", "source": "gau"}}
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        await handler(Event(type="discovery", payload=event))
        await handler(Event(type="discovery", payload=event))
        await handler(Event(type="discovery", payload=event | {"data": {"url": "https://outside.invalid/x"}}))
    assert stats["historical_urls"] == 1
    assert len(storage.relationships) == 1
    relationship = next(iter(storage.relationships.values()))
    assert relationship.type == "HISTORICAL_URL"
    assert len(evidence.records) == 4


asyncio.run(handler_check())

with tempfile.TemporaryDirectory() as directory:
    database = str(Path(directory) / "report.db")
    with sqlite3.connect(database) as db:
        db.executescript("""
        CREATE TABLE nodes (id TEXT, type TEXT, value TEXT, attributes TEXT);
        CREATE TABLE relationships (id TEXT, from_id TEXT, to_id TEXT, type TEXT, attributes TEXT);
        CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT);
        CREATE TABLE evidence (scan_run_id TEXT, kind TEXT, content TEXT);
        """)
        db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)", ("domain:example.com", "domain", "example.com", "{}"))
        db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)", ("url:https://example.com/old", "url", "https://example.com/old", "{}"))
        db.execute("INSERT INTO relationships VALUES (?, ?, ?, ?, ?)", ("history", "domain:example.com", "url:https://example.com/old", "HISTORICAL_URL", "{}"))
        db.execute("INSERT INTO scan_assets VALUES (?, ?, ?, ?)", ("scan-1", "url:https://example.com/old", "history", "url-history"))
    run = ScanRun("scan-1", "example.com", "start", "end", "COMPLETED")
    report = build_scan_report(database, run)
    assert report.historical_urls == 1
    assert report.http_endpoints == 0
    output = Path(directory) / "report.json"
    assert export_scan(database, run, format="json", output=output) == 1
    assert json.loads(output.read_text())["assets"][0]["type"] == "historical-url"

print("url history pipeline test passed")
