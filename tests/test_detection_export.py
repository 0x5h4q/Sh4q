"""What a defender would see, derived from what the scan actually did.

The disclosure ledger answers "who did this tell about my target". This
answers the other question a blue team asks: "what does this look like
from my side, and could I have caught it?"

Two things make it worth more than a folder of hand-written Sigma rules.

The thresholds are measured, not guessed. A scan that made 1500 DNS
queries in 166 seconds yields a rule whose threshold comes from that,
not from a template. Nobody has to argue about whether 30 queries in 10
seconds is realistic -- the number is what the tool did.

And it states which of its own actions a defender cannot see. Certificate
transparency, Subfinder and URL history never touch the target, so no log
on that side records them. A detection artifact that claims coverage of
passive reconnaissance would be lying, and the gap is the useful part:
you cannot detect the stage that found your subdomains, only the stage
that probed them.

Read from durable evidence, like the disclosure ledger, so it also works
on scans already on disk.
"""

import asyncio
import os
import sqlite3
import tempfile
from pathlib import Path

from sh4q.application.detection import summarize_detections
from sh4q.storage.evidence import Evidence, SQLiteEvidenceStore

SCAN = "scan-1"
TARGET = "example.com"


def record(kind, plugin, index, second):
    return Evidence(
        id=f"{kind}-{index}", target=TARGET, plugin=plugin, kind=kind,
        content={"domain": f"h{index}.{TARGET}"},
        scan_run_id=SCAN,
        captured_at=f"2026-10-08T12:00:{second:02d}+00:00",
    )


async def main() -> None:
    handle, db_path = tempfile.mkstemp(prefix="sh4q_detection_", suffix=".db")
    os.close(handle)
    os.remove(db_path)
    try:
        store = SQLiteEvidenceStore(db_path)
        await store.init()

        # 40 DNS lookups across 20 seconds, and 10 HTTP probes across 10.
        for index in range(40):
            await store.append(record("discovered_dns_resolution", "discovered-dns", index, index // 2))
        for index in range(10):
            await store.append(record("http_probe", "discovered-http", index, 20 + index))
        # Passive stages: real, and invisible from the target's side.
        for index in range(5):
            await store.append(record("subdomain_found", "ct", index, 0))

        report = summarize_detections(db_path, scan_id=SCAN)
        by_signal = {d.signal: d for d in report.detections}

        # --- thresholds come from the scan, not a template ----------------
        dns = by_signal["subdomain_enumeration"]
        assert dns.observed == 40, dns
        assert dns.window_seconds == 19.0, dns.window_seconds
        assert 2.0 < dns.rate < 2.2, dns.rate
        assert dns.visible_to_target is True
        assert dns.log_source == "dns"
        # Sigma tags are lowercase by convention, so the rule and the record
        # carry the same string and a reader can grep for either.
        assert "attack.t1590.002" in dns.attack, dns.attack

        http = by_signal["http_probing"]
        assert http.observed == 10 and http.visible_to_target is True
        assert http.log_source == "webserver"

        # --- what a defender cannot see is stated, not omitted ------------
        passive = by_signal["certificate_transparency"]
        assert passive.visible_to_target is False, (
            "CT never touches the target; claiming it is detectable would be false"
        )
        assert passive.log_source == "", passive.log_source
        assert passive.observed == 5

        assert len(report.visible) == 2 and len(report.invisible) == 1, (
            [(d.signal, d.visible_to_target) for d in report.detections]
        )

        # --- a rule is emitted only for what is actually detectable -------
        rules = report.to_sigma_rules()
        assert set(rules) == {
            "sh4q_subdomain_enumeration.yml", "sh4q_http_probing.yml",
        }, sorted(rules)
        rule = rules["sh4q_subdomain_enumeration.yml"]
        assert "title:" in rule and "logsource:" in rule and "detection:" in rule
        assert "attack.t1590.002" in rule.lower(), rule
        assert "40" in rule, "the measured count must reach the rule"
        assert "level:" in rule

        # --- telemetry is one line per signal, machine readable -----------
        import json

        lines = [json.loads(line) for line in report.to_telemetry_jsonl().splitlines()]
        assert len(lines) == 3, lines
        assert {"scan_id", "target", "signal", "observed", "window_seconds",
                "rate_per_second", "visible_to_target", "attack", "log_source"} <= set(lines[0])

        # --- a scan with nothing recorded claims nothing -------------------
        empty = summarize_detections(db_path, scan_id="absent")
        assert empty.detections == () and empty.to_sigma_rules() == {}

        # --- the export surface writes a directory, and only its own ------
        # `sigma` is the one format whose --output is a directory, so the
        # usual "write one file" path does not apply to it.
        from sh4q.application.exporter import export_scan
        from sh4q.storage.scan_runs import ScanRun

        with sqlite3.connect(db_path) as connection:
            connection.executescript(
                "CREATE TABLE IF NOT EXISTS nodes (id TEXT, type TEXT, value TEXT, attributes TEXT);"
                "CREATE TABLE IF NOT EXISTS relationships (id TEXT, from_id TEXT, to_id TEXT, type TEXT, attributes TEXT);"
                "CREATE TABLE IF NOT EXISTS scan_assets (scan_run_id TEXT, asset_id TEXT, relationship_id TEXT, source_plugin TEXT);"
            )
            connection.execute(
                "INSERT INTO nodes VALUES (?, ?, ?, ?)",
                (f"domain:{TARGET}", "domain", TARGET, "{}"),
            )
            connection.execute(
                "INSERT INTO scan_assets VALUES (?, ?, ?, ?)",
                (SCAN, f"domain:{TARGET}", None, "dns"),
            )

        run = ScanRun(SCAN, TARGET, "start", "end", "COMPLETED")
        destination = Path(db_path).with_suffix(".rules")
        count = export_scan(db_path, run, format="sigma", output=destination)
        written = {path.name for path in destination.iterdir()}
        assert written == {
            "sh4q_subdomain_enumeration.yml",
            "sh4q_http_probing.yml",
            "telemetry.jsonl",
        }, written
        assert int(count) == 2, count
        assert "certificate_transparency" not in " ".join(written), (
            "a rule for an invisible stage could never fire"
        )

        # A rule left over from an earlier export is a rule the operator did
        # not ask for, sitting in the directory they hand to a defender.
        stale = destination / "sh4q_directory_enumeration.yml"
        stale.write_text("title: from an earlier scan\n", encoding="utf-8")
        operator_file = destination / "notes.md"
        operator_file.write_text("mine\n", encoding="utf-8")
        export_scan(db_path, run, format="sigma", output=destination, force=True)
        assert not stale.exists(), "a stale rule must not survive a re-export"
        assert operator_file.exists(), "only files this exporter names may be removed"

        print("detection export test passed")
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


asyncio.run(main())
