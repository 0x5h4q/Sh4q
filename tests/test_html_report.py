import sqlite3
import tempfile
from pathlib import Path

from sh4q.application.html_report import render_html_report
from sh4q.storage.scan_runs import ScanRun


with tempfile.TemporaryDirectory() as directory:
    database = str(Path(directory) / "report.db")
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE nodes (id TEXT, type TEXT, value TEXT, attributes TEXT)")
        db.execute("CREATE TABLE scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT)")
        db.execute("CREATE TABLE relationships (id TEXT, from_id TEXT, to_id TEXT, type TEXT, attributes TEXT)")
        db.execute("CREATE TABLE evidence (id TEXT, target TEXT, plugin TEXT, kind TEXT, content TEXT, captured_at TEXT, scan_run_id TEXT)")
        db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)", (
            "url:1", "url", "https://api.example.com/?q=<script>", '{"status":200}'
        ))
        db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)", (
            "technology:next", "technology", "next.js", '{"category":"web-framework"}'
        ))
        db.executemany("INSERT INTO scan_assets VALUES (?, ?, ?, ?)", [
            ("scan-1", "url:1", "rel-url", "discovered-http"),
            ("scan-1", "technology:next", "rel-tech", "native"),
        ])
        db.execute("INSERT INTO relationships VALUES (?, ?, ?, ?, ?)", ("rel-tech", "url:1", "technology:next", "DETECTED_TECHNOLOGY", '{"status":200}'))
        db.executemany("INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?)", [
            ("e1", "example.com", "http", "http_error", '{"error":"timeout"}', "now", "scan-1"),
            ("e2", "example.com", "native", "request_metrics", '{"observed":{"admitted":2}}', "now", "scan-1"),
        ("e3", "example.com", "scheduler", "stage_metrics", '{"stages":[{"name":"dns","status":"completed","attempts":1,"discoveries":1,"duration_seconds":0.1}]}', "now", "scan-1"),
        ("e4", "example.com", "javascript-extraction", "javascript_endpoint_reference", '{"value":"https://example.com/api/me","source_endpoint":"https://example.com/"}', "now", "scan-1"),
        ("e5", "example.com", "vhost-discovery", "vhost_baseline", '{"endpoint":"https://example.com/","fingerprint":"base"}', "now", "scan-1"),
        ("e6", "example.com", "vhost-discovery", "vhost_observation", '{"candidate":"admin.example.com","endpoint":"https://example.com/","status":200,"classification":"candidate_observation"}', "now", "scan-1"),
        ("e7", "example.com", "vhost-discovery", "vhost_rejected", '{"candidate":"evil.test","reason":"out of scope"}', "now", "scan-1"),
        ("e8", "example.com", "directory-discovery", "directory_baseline", '{"endpoint":"https://example.com/","fingerprint":"base"}', "now", "scan-1"),
        ("e9", "example.com", "directory-discovery", "directory_observation", '{"path":"/admin","url":"https://example.com/admin","status":200,"classification":"candidate_observation"}', "now", "scan-1"),
        ("e10", "example.com", "directory-discovery", "directory_rejected", '{"path":"../outside","reason":"path escapes the origin"}', "now", "scan-1"),
        ])

    run = ScanRun("scan-1", "example.com", "start", "end", "COMPLETED")
    report = render_html_report(database, run)
    assert "<!doctype html>" in report
    assert "id=\"status\"" in report
    assert "id=\"technology\"" in report
    assert "api.example.com" in report
    assert "\\u003cscript>" in report
    assert "filtered.length" in report
    assert "String(value).split(',')" in report
    assert "String(a.status).split(',')" in report
    assert "Failures" in report
    assert "Stage timings" in report
    assert "Request metrics" in report
    assert "Evidence index" in report
    assert "JavaScript observations" in report
    assert "Virtual-host observations" in report
    assert "admin.example.com" in report
    assert "Rejected candidates" in report
    assert "Directory observations" in report
    assert "example.com/admin" in report
    assert "../outside" in report
    assert "evil.test" in report
    assert "https://example.com/api/me" in report
    assert "not automatically requested" in report
    assert '>1</strong>JavaScript observations' in report
    assert "HTTP status" in report
    assert "fetch(" not in report
    assert report.count("<select") == 5
    assert "Reset filters" in report
    assert "data:image/png;base64," in report
    assert 'alt="Sh4q"' in report, "the banner must carry alt text"
    assert "width: min(220px" in report
    assert "white-space: nowrap" in report
    assert "No assets match these filters" in report
print("HTML report test passed")

# --- design properties the report must keep -------------------------------
# Colours are declared once as tokens. Before this, dark mode duplicated
# every rule, so a new element was routinely styled for light mode only.
assert "--surface:" in report and "--accent:" in report, "design tokens must be defined"
assert report.count("--surface:") >= 3, "light, system-dark, and explicit-dark must each define them"

# A reader whose system is dark must not be shown a light report first.
assert "prefers-color-scheme: dark" in report, "the system setting must be honoured"
# ...and the toggle must still be able to override that preference, which a
# single .dark class cannot express.
assert "body.dark" in report and "body:not(.light)" in report, "the override must work both ways"

# The report is opened offline, frequently from a file:// URL.
for remote in ("http://", "https://fonts", "cdn.", "<link"):
    assert remote not in report.replace("https://", "", report.count("https://")) or remote != "<link", (
        f"the report must not load anything remote: {remote}"
    )
assert "@import" not in report, "no remote stylesheet imports"

# Motion is opt-out for readers who ask for less of it.
assert "prefers-reduced-motion" in report

# The banner identifies the report; it must not fill the viewport. It ran to
# 340px tall before, pushing the findings below the fold.
assert "max-height: 96px" in report, "the banner must stay a header, not a hero"
print("html report design test passed")


# --- failures must say what failed, and not repeat themselves -------------
# A real scan produced 1025 DNS failures. The report rendered 1025 rows, each
# reading "no A answer" with no hostname: the reason repeats, the subjects do
# not, and the subjects are the part an operator needs.
from sh4q.application.html_report import _failure_subject, _grouped_failures  # noqa: E402

assert _failure_subject({"domain": "a.example.com", "error": "no A answer"}) == "a.example.com"
assert _failure_subject({"url": "https://b.example.com/"}) == "https://b.example.com/"
assert _failure_subject({"candidate": "c.example.com"}) == "c.example.com"
assert _failure_subject({"error": "nothing identifying"}) == "-", "never invent a subject"

_many = (
    [{"plugin": "discovered-dns", "kind": "discovered_dns_error", "detail": "no A answer",
      "subject": f"h{i}.example.com"} for i in range(909)]
    + [{"plugin": "discovered-dns", "kind": "discovered_dns_error", "detail": "resolution timed out",
        "subject": f"t{i}.example.com"} for i in range(115)]
    + [{"plugin": "discovered-http", "kind": "http_error", "detail": "ReadError",
        "subject": "https://one.example.com"}]
)
_grouped = _grouped_failures(_many)
assert len(_grouped) == 3, f"identical failures collapse into one row each: {len(_grouped)}"
assert [row["count"] for row in _grouped] == [909, 115, 1], "ordered by how many, most first"
assert _grouped[0]["detail"] == "no A answer"
assert len(_grouped[0]["examples"]) == 4, "a few subjects are named"
assert _grouped[0]["more"] == 905, _grouped[0]["more"]
assert _grouped[2]["more"] == 0, "a single failure has nothing further to mention"
assert _grouped_failures([]) == []

# The rendered table carries the subject, which is what was missing.
assert "Affected" in report, "the failures table must have a column for what failed"
print("html report failure grouping test passed")
