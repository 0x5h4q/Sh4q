import json
import sqlite3
import tempfile
from pathlib import Path

from sh4q.application.exporter import export_scan
from sh4q.application.redaction import redact_url
from sh4q.storage.scan_runs import ScanRun

# The marker's brackets are left literal. Percent-encoded as
# %5BREDACTED%5D it is far harder to recognise in a report handed to
# someone else, which is the only reason the report exists.
assert redact_url("https://example.com/path?view=full&token=abc#frag") == "https://example.com/path?view=full&token=[REDACTED]"
assert redact_url("https://example.com/path") == "https://example.com/path"

# A URL with nothing to redact must come back byte-for-byte. Round-tripping the
# query through urlencode rewrote queries it had no business touching: a bare
# cache-buster parses as one valueless key and came back out with a trailing
# "=", so --redact silently altered 8 of the 238 URLs in a real scan. A
# redacted report must differ from the observation only where a secret was
# removed, or it is not a record of what was seen.
for untouched in (
    "https://example.com/app.js?0808dd08ad62f5774e5f045e2ce6d08b",
    "https://example.com/p?a=1&a=2",
    "https://example.com/p?q=hello%20world",
    "https://example.com/p?view=full",
    "https://example.com/",
):
    assert redact_url(untouched) == untouched, f"{untouched} -> {redact_url(untouched)}"

# The fragment is still dropped, which is deliberate and predates this.
assert redact_url("https://example.com/p?token=a#frag") == "https://example.com/p?token=[REDACTED]"

with tempfile.TemporaryDirectory() as directory:
    database = str(Path(directory) / "redact.db")
    with sqlite3.connect(database) as db:
        db.executescript("CREATE TABLE nodes (id TEXT, type TEXT, value TEXT, attributes TEXT); CREATE TABLE relationships (id TEXT, from_id TEXT, to_id TEXT, type TEXT, attributes TEXT); CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT); CREATE TABLE evidence (scan_run_id TEXT);")
        db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)", ("url:https://example.com/path?token=abc", "url", "https://example.com/path?token=abc", "{}"))
        db.execute("INSERT INTO scan_assets VALUES (?, ?, ?, ?)", ("scan", "url:https://example.com/path?token=abc", "rel", "test"))
    output = Path(directory) / "report.json"
    run = ScanRun("scan", "example.com", "start", "end", "COMPLETED")
    result = export_scan(database, run, format="json", output=output, redact=True)
    document = json.loads(output.read_text())
    assert "REDACTED" in document["assets"][0]["value"]
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT value FROM nodes").fetchone()[0].endswith("token=abc")

    # --- redaction has to say what it did ---------------------------------
    # This printed the same "Exported N asset(s)" line whether it rewrote
    # four hundred values or none. Verifying it against a database whose URLs
    # carry no query string produced a byte-identical file and looked like a
    # pass -- and so would a regression that silently stopped redacting.
    assert result.redaction_enabled is True
    assert result.fields_considered == 1, result
    assert result.fields_redacted == 1, result
    assert "rewrote 1 of 1" in result.redaction_summary, result.redaction_summary

    # An export with redaction off says nothing about it.
    plain = export_scan(database, run, format="json", output=output, redact=False, force=True)
    assert plain.redaction_summary == "", plain.redaction_summary
    assert plain.fields_redacted == 0

    # The asset count still reads as a count, which several callers rely on.
    assert plain == 1 and int(plain) == 1, plain

print("export redaction test passed")


# --- redaction reached only one field of one asset type --------------------
# `--redact` rewrote the `value` of url assets and nothing else, so the
# technology CSV's endpoint column, the HTTP-inventory endpoint column, and
# the exported JavaScript observations went out untouched. The last of those
# is where an extracted URL most often carries a key.
import csv  # noqa: E402

SECRET = "https://example.com/api?api_key=live-123"

with tempfile.TemporaryDirectory() as directory:
    database = str(Path(directory) / "wide.db")
    with sqlite3.connect(database) as db:
        db.executescript("""
            CREATE TABLE nodes (id TEXT, type TEXT, value TEXT, attributes TEXT);
            CREATE TABLE relationships (id TEXT, from_id TEXT, to_id TEXT, type TEXT, attributes TEXT);
            CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT);
            CREATE TABLE evidence (id TEXT, scan_run_id TEXT, target TEXT, plugin TEXT, kind TEXT, content TEXT, captured_at TEXT);
        """)
        db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)", (f"url:{SECRET}", "url", SECRET, "{}"))
        db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)", ("technology:nginx", "technology", "nginx", "{}"))
        db.execute(
            "INSERT INTO relationships VALUES (?, ?, ?, ?, ?)",
            ("rel-tech", f"url:{SECRET}", "technology:nginx", "DETECTED_TECHNOLOGY",
             json.dumps({"category": "web-server", "source": "native", "status": 200})),
        )
        db.execute("INSERT INTO scan_assets VALUES (?, ?, ?, ?)", ("scan", f"url:{SECRET}", None, "http"))
        db.execute("INSERT INTO scan_assets VALUES (?, ?, ?, ?)", ("scan", None, "rel-tech", "http"))
        db.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("e1", "scan", "example.com", "javascript-extraction",
             "javascript_endpoint_reference",
             json.dumps({"value": SECRET, "source_endpoint": SECRET, "pattern": "fetch"}),
             "2026-01-01T00:00:00Z"),
        )

    run = ScanRun("scan", "example.com", "start", "end", "COMPLETED")

    json_out = Path(directory) / "wide.json"
    export_scan(database, run, format="json", output=json_out, redact=True)
    body = json_out.read_text()
    assert "live-123" not in body, "a redacted export must not carry the secret anywhere"
    document = json.loads(body)
    observation = document["javascript_observations"][0]
    assert "REDACTED" in observation["value"], observation
    assert "REDACTED" in observation["source_endpoint"], observation

    csv_out = Path(directory) / "tech.csv"
    export_scan(database, run, format="csv", output=csv_out, asset_type="technology", redact=True)
    tech_body = csv_out.read_text()
    assert "live-123" not in tech_body, tech_body
    assert "REDACTED" in next(csv.DictReader(tech_body.splitlines()))["endpoint"]

    html_out = Path(directory) / "wide.html"
    export_scan(database, run, format="html", output=html_out, redact=True)
    assert "live-123" not in html_out.read_text()

print("wide export redaction test passed")
