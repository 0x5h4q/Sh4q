import sqlite3
import tempfile
from pathlib import Path

from sh4q.application.fingerprint_inputs import scan_fingerprint_endpoints
from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine


with tempfile.TemporaryDirectory() as directory:
    database = str(Path(directory) / "fingerprints.db")
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE nodes (id TEXT, type TEXT, value TEXT, attributes TEXT)")
        db.execute("CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT)")
        db.executemany("INSERT INTO nodes VALUES (?, ?, ?, ?)", [
            ("url:https://api.example.com/", "url", "https://api.example.com/", "{}"),
            ("url:https://evil.test/", "url", "https://evil.test/", "{}"),
            ("url:ftp://files.example.com/", "url", "ftp://files.example.com/", "{}"),
            ("url:https://old.example.com/", "url", "https://old.example.com/", "{}"),
        ])
        db.executemany("INSERT INTO scan_assets VALUES (?, ?, ?, ?)", [
            ("scan-1", "url:https://api.example.com/", "rel-1", "http"),
            ("scan-1", "url:https://evil.test/", "rel-2", "http"),
            ("scan-1", "url:ftp://files.example.com/", "rel-3", "test"),
            ("scan-old", "url:https://old.example.com/", "rel-4", "http"),
        ])

    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    endpoints = scan_fingerprint_endpoints(database, "scan-1", scope)
    assert endpoints == ["https://api.example.com/"]
    assert scan_fingerprint_endpoints(database, "scan-old", scope) == [
        "https://old.example.com/"
    ]
print("fingerprint input selection test passed")
