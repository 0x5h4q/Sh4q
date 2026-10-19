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
import uuid
import tempfile
from dataclasses import replace
from pathlib import Path

from sh4q.application.detection import (
    MINIMUM_THRESHOLD,
    RULE_WINDOW_SECONDS,
    DetectionReport,
    summarize_detections,
)
from sh4q.storage.evidence import Evidence, SQLiteEvidenceStore

SCAN = "scan-1"
BURST = "scan-burst"
SPLIT = "scan-split"
BATCH = "scan-batch"
TARGET = "example.com"


def stage_metrics(stages, scan=None):
    """The record every stage leaves behind, and the detection denominator.

    Without this the fixture could not express the defect it now guards:
    `captured_at` is when a row was *written*, so a stage that batches its
    discoveries looks instantaneous. The real pipeline always writes this.
    """
    scan = scan or SCAN
    return Evidence(
        id=f"stage-metrics-{scan}", target=TARGET, plugin="sh4q", kind="stage_metrics",
        content={"stages": [
            {"name": name, "duration_seconds": seconds, "status": "completed"}
            for name, seconds in stages.items()
        ]},
        scan_run_id=scan,
        captured_at="2026-10-08T12:01:00+00:00",
    )


def record(kind, plugin, index, second, scan=None):
    return Evidence(
        id=f"{kind}-{plugin}-{index}-{scan or SCAN}", target=TARGET,
        plugin=plugin, kind=kind,
        content={"domain": f"h{index}.{TARGET}"},
        scan_run_id=scan or SCAN,
        captured_at=f"2026-10-08T12:00:{second:02d}+00:00",
    )


async def main() -> None:
    handle, db_path = tempfile.mkstemp(prefix="sh4q_detection_", suffix=".db")
    os.close(handle)
    os.remove(db_path)
    try:
        store = SQLiteEvidenceStore(db_path)
        await store.init()

        # 40 DNS lookups and 10 HTTP probes. Every `captured_at` below is a
        # burst -- which is exactly what the real directory stage does -- so
        # the rate can only come from the recorded stage durations.
        for index in range(40):
            await store.append(record("discovered_dns_resolution", "discovered-dns", index, index // 2))
        for index in range(10):
            await store.append(record("http_probe", "discovered-http", index, 20 + index))
        # Passive stages: real, and invisible from the target's side.
        for index in range(5):
            await store.append(record("subdomain_found", "ct", index, 0))
        await store.append(stage_metrics({
            "discovered-dns": 19.0, "discovered-http": 9.901, "ct": 0.55,
        }))

        report = summarize_detections(db_path, scan_id=SCAN)
        by_signal = {d.signal: d for d in report.detections}

        # --- thresholds come from the scan, not a template ----------------
        dns = by_signal["subdomain_enumeration"]
        assert dns.observed == 40, dns
        # The window is the stage's own recorded duration, not the span
        # between evidence rows. Those rows were written in a burst.
        assert dns.window_seconds == 19.0, dns.window_seconds
        assert dns.rate_measured is True
        assert 2.0 < dns.rate < 2.2, dns.rate
        assert dns.visible_to_target is True
        assert dns.log_source == "dns"
        # Sigma tags are lowercase by convention, so the rule and the record
        # carry the same string and a reader can grep for either.
        assert "attack.t1590.002" in dns.attack, dns.attack

        http = by_signal["http_probing"]
        assert http.observed == 10 and http.visible_to_target is True
        # Two stages feed this signal, so the window is the sum of both.
        assert http.window_seconds == 9.901, http.window_seconds
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
        assert "40 observable event(s)" in rule, (
            "the measured count must reach the rule"
        )
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

        # --- the rate is of requests, not of database writes --------------
        # Found by reading a real scan. The directory stage probes every
        # candidate with a 1s sleep between them, then returns them together,
        # so the handler appended all six evidence rows inside 0.195s. The
        # span between `captured_at` values gave 30.89 requests per second
        # for six requests over 31 seconds -- inflated 162x -- which
        # projected to a threshold of 926 on a stage that made six requests.
        # An unfireable rule, which is the exact defect this module was
        # already supposed to have fixed once.
        for index in range(6):
            await store.append(record(
                "directory_observation", "directory-discovery", index, 0, scan=BURST))
        await store.append(stage_metrics({"directory-discovery": 31.574}, scan=BURST))
        burst_report = summarize_detections(db_path, scan_id=BURST)
        directory = {d.signal: d for d in burst_report.detections}["directory_enumeration"]
        assert directory.observed == 6, directory
        assert directory.window_seconds == 31.574, (
            "the window must be the stage's recorded duration, not the span "
            f"between evidence rows: {directory.window_seconds}"
        )
        assert 0.18 < directory.rate < 0.20, (
            f"six requests over 31.574s is ~0.19/s, not {directory.rate}"
        )
        # And the threshold that falls out of it has to be reachable.
        floor_rule = burst_report.to_sigma_rules()["sh4q_directory_enumeration.yml"]
        assert f"gte: {MINIMUM_THRESHOLD}" in floor_rule, floor_rule

        # --- one kind, two sources, two different third parties -----------
        # `subdomain_found` is emitted by both `ct` and `subfinder`. Matching
        # on kind alone made the certificate-transparency row report 2961
        # names on a real scan, 1211 of which came from Subfinder and had
        # nothing to do with certificate transparency.
        for index in range(5):
            await store.append(record("subdomain_found", "ct", index, 0, scan=SPLIT))
        for index in range(7):
            await store.append(record("subdomain_found", "subfinder", index, 0, scan=SPLIT))
        await store.append(stage_metrics({"ct": 0.55, "subfinder": 3.0}, scan=SPLIT))
        split = {d.signal: d for d in summarize_detections(db_path, scan_id=SPLIT).detections}
        assert split["certificate_transparency"].observed == 5, (
            f"CT must count only its own evidence: {split['certificate_transparency']}"
        )
        assert split["passive_subdomain_adapter"].observed == 7, split
        # Neither is visible, so neither may produce a rule.
        assert not split["passive_subdomain_adapter"].visible_to_target
        assert "sh4q_passive_subdomain_adapter.yml" not in (
            summarize_detections(db_path, scan_id=SPLIT).to_sigma_rules()
        )

        # --- one record can stand for thousands of observations -----------
        # url-history writes a single batch row. Counting rows reported
        # "1 event" next to the 4996 URLs it had just saved.
        await store.append(Evidence(
            id="batch-1", target=TARGET, plugin="url-history",
            kind="url_history_batch",
            content={"domain": TARGET, "urls": [f"https://h{n}.{TARGET}/" for n in range(2500)]},
            scan_run_id=BATCH, captured_at="2026-10-08T12:00:30+00:00",
        ))
        await store.append(stage_metrics({"url-history": 50.0}, scan=BATCH))
        batched = {d.signal: d for d in summarize_detections(db_path, scan_id=BATCH).detections}
        history = batched["historical_url_retrieval"]
        assert history.observed == 2500, (
            f"a batch of 2500 URLs is not one observation: {history.observed}"
        )
        assert history.visible_to_target is False

        # --- an unmeasurable rate is not a rate of zero -------------------
        # A scan interrupted before it wrote stage_metrics, or one recorded
        # before that evidence existed, leaves no denominator. Reporting
        # 0.00/s and a floor threshold as though they were measured would be
        # the same lie in a quieter voice.
        handle2, bare_path = tempfile.mkstemp(prefix="sh4q_detection_bare_", suffix=".db")
        os.close(handle2)
        os.remove(bare_path)
        try:
            bare = SQLiteEvidenceStore(bare_path)
            await bare.init()
            for index in range(9):
                await bare.append(record(
                    "discovered_dns_resolution", "discovered-dns", index, index))
            unmeasured = summarize_detections(bare_path, scan_id=SCAN).detections[0]
            assert unmeasured.observed == 9
            assert unmeasured.window_seconds == 0.0
            assert unmeasured.rate_measured is False, (
                "no stage duration means the rate is unknown, not zero"
            )
            text = summarize_detections(bare_path, scan_id=SCAN).to_sigma_rules()[
                "sh4q_subdomain_enumeration.yml"]
            assert f"gte: {MINIMUM_THRESHOLD}" in text, text
            assert "no rate could be" in text, (
                f"the rule must admit the threshold is not a measurement: {text}"
            )
            assert "/s)" not in text, "it must not quote a rate it never measured"
        finally:
            if os.path.exists(bare_path):
                os.remove(bare_path)

        # --- the rule is valid Sigma, not just plausible YAML -------------
        # Everything here was found by running the real validator (pySigma)
        # over the exported rules. By eye the first version read fine and was
        # rejected outright on two counts, so these are structural assertions
        # a reader cannot talk themselves out of.

        # `id` must be a UUID. `id: sh4q-subdomain-enumeration` is readable
        # and not a valid Sigma identifier.
        ids = [
            line.split("id:", 1)[1].strip()
            for line in rule.splitlines() if line.startswith("id:")
        ]
        assert len(ids) == 2, ids
        for value in ids:
            uuid.UUID(value)          # raises if it is not a real UUID
        assert ids[0] != ids[1], "the two documents need distinct identifiers"

        # And it must be stable, or a defender's tooling sees a brand new rule
        # on every export instead of a revision of the one they already tuned.
        again = DetectionReport(
            report.scan_id, report.target, report.detections, scans=report.scans,
        ).to_sigma_rules()
        assert again["sh4q_subdomain_enumeration.yml"] == rule, (
            "re-exporting the same measurements must reproduce the same rule"
        )

        # The single-document aggregation form is deprecated Sigma and pySigma
        # refuses it: "the pipe syntax has been deprecated and replaced by
        # Sigma correlations". A rule using it loads nowhere.
        assert "|" not in rule, f"deprecated pipe/aggregation syntax: {rule}"
        assert "timeframe:" not in rule, "timeframe belongs to the old form"

        # The modern form is two documents: the events, and a correlation over
        # them, joined by `name`.
        documents = rule.split("\n---\n")
        assert len(documents) == 2, documents
        events, correlation = documents
        assert "correlation:" not in events and "detection:" in events
        assert "correlation:" in correlation and "detection:" not in correlation
        assert "name: sh4q_subdomain_enumeration_events" in events
        assert "    - sh4q_subdomain_enumeration_events" in correlation, (
            "the correlation must reference the base rule by the name it declares"
        )
        # Recon is breadth, not volume -- distinct names, not request count.
        assert "type: value_count" in correlation, correlation
        assert "field: query_name" in correlation
        assert "    - src_ip" in correlation, "the count must be per source"
        # The base rule alone matches ordinary traffic; only the correlation
        # is an alert, and the levels have to say so.
        assert "level: informational" in events, events
        assert "level: medium" in correlation, correlation

        # --- the window is fixed, and the threshold derived from it -------
        # The guard on the defect this module shipped with: the first version
        # used the measured span as the window, so a throttled scan produced
        # 62813s with a threshold of 1887 -- a rule that can never fire. The
        # span is a property of the rate limit, not of the behaviour.
        assert f"timespan: {RULE_WINDOW_SECONDS}s" in correlation, correlation
        assert str(int(dns.window_seconds)) not in (
            correlation.split("timespan:")[1]
        ), "the measured span must not reach the rule as its window"

        # 40 events over 19s is 2.105/s; a 60s window sees 126, half is 63.
        expected = int(dns.rate * RULE_WINDOW_SECONDS * 0.5)
        assert expected == 63, expected
        assert f"gte: {expected}" in correlation, correlation
        # The rate must be quoted beside the threshold, or the number is
        # unarguable only to whoever generated it.
        assert f"{dns.rate:.2f}/s" in correlation, correlation

        # A rate low enough to project under the floor must still produce a
        # usable rule. A real scan throttled to a crawl measures a fraction of
        # an event per second, and `int(0.01 * 60 * 0.5)` is 0 -- a rule that
        # matches the first DNS query any host makes.
        crawling = replace(dns, rate=0.01)
        assert int(crawling.rate * RULE_WINDOW_SECONDS * 0.5) == 0, "pre-condition"
        floored = DetectionReport(SCAN, TARGET, (crawling,)).to_sigma_rules()
        body = floored["sh4q_subdomain_enumeration.yml"]
        assert f"gte: {MINIMUM_THRESHOLD}" in body, (
            f"a threshold near zero would alert on ordinary traffic: {body}"
        )

        # --- the view states what it is showing ---------------------------
        # Every defect this project has shipped in this class was in rendered
        # output, not in the model behind it, so the view is asserted too.
        import contextlib
        import io

        from sh4q.cli.main import render_detections

        screen = io.StringIO()
        with contextlib.redirect_stdout(screen):
            render_detections(report)
        shown = screen.getvalue()

        for item in report.detections:
            assert item.signal in shown, f"{item.signal} missing from the view"
            assert str(item.observed) in shown, f"{item.observed} missing"
        # An invisible stage must be marked as such on screen, not merely
        # omitted from the rules -- the gap is the useful part.
        assert "not visible" in shown, shown
        assert "certificate_transparency" in shown.split("none is written:")[1], (
            "the invisible stage must be named where the view explains itself"
        )
        assert "One stage never contacts" in shown, shown
        assert "records it." in shown, "singular case must agree in number"

        # Averaging several scans into one rate is misleading unless said.
        assert "Measured across" not in shown, (
            "a single-scan report must not claim an average"
        )
        many = DetectionReport(SCAN, TARGET, report.detections, scans=3)
        multi = io.StringIO()
        with contextlib.redirect_stdout(multi):
            render_detections(many)
        assert "Measured across 3 scans" in multi.getvalue()
        assert "average" in multi.getvalue()

        # The plural branch of that sentence is reached by a report whose
        # invisible signals number more than one.
        pair = DetectionReport(SCAN, TARGET, tuple(
            d for d in report.detections if not d.visible_to_target
        ) * 2)
        plural = io.StringIO()
        with contextlib.redirect_stdout(plural):
            render_detections(pair)
        assert "2 stages never contact" in plural.getvalue(), plural.getvalue()
        assert "records them." in plural.getvalue()

        # A report with nothing in it says so, rather than printing a header
        # over an empty table.
        blank = io.StringIO()
        with contextlib.redirect_stdout(blank):
            render_detections(DetectionReport(SCAN, TARGET, ()))
        assert "Nothing recorded" in blank.getvalue(), blank.getvalue()

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
