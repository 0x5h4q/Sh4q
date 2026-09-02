import io
import os
import shutil
import sys
from types import SimpleNamespace

from sh4q.cli.branding import SCAN_BANNER, render_scan_banner
from sh4q.cli.main import render_event_results, render_failure_results, render_scan_runs, render_technology_results, render_scan_report, render_summary


class NarrowOutput(io.StringIO):
    def isatty(self):
        return True


original_stdout = sys.stdout
original_terminal_size = shutil.get_terminal_size
output = NarrowOutput()
try:
    sys.stdout = output
    shutil.get_terminal_size = lambda fallback=(80, 24): os.terminal_size((60, 24))
    render_technology_results([SimpleNamespace(endpoint="https://very-long-hostname.example.com/path", technology="cloudflare", version="", category="cdn", confidence="high", source="native-signature", status=403, signal="x" * 100)])
    render_event_results([SimpleNamespace(status="FAILED", type="discovery", source_plugin="http", discovery_kind="http_error", target="a" * 80, attempts=3, id="b" * 80, error="c" * 100)])
    render_scan_runs([(SimpleNamespace(status="COMPLETED", target="d" * 80, started_at="2026-08-30T00:00:00", id="e" * 80), 12)])
    render_failure_results([("discovered-http", "http_error", "f" * 120)])
    render_summary(SimpleNamespace(
        target="very-long-target.example.com", scan_run_id="a" * 40,
        scope_allowed=True, recovered_events=0, dns_addresses=1,
        http_endpoints=1, ct_names=1, adapter_names=1,
        resolved_discovered_addresses=1, resolved_discovered_failures=1,
        dns_failure_reasons={}, technologies=1, discoveries=5,
        relationships=4, evidence_this_scan=6, evidence=6,
        requests_admitted=2, requests_denied=0, requests_completed=2,
        requests_failed=0, peak_request_concurrency=1,
        stage_durations={}, duration_seconds=1.2,
        database_path="/very/long/path/to/sh4q-output/sh4q.db",
    ))
    render_scan_report(SimpleNamespace(
        run=SimpleNamespace(target="very-long-target.example.com", id="b" * 40,
                            status="COMPLETED", started_at="2026-09-02T00:00:00+00:00", completed_at=None),
        request_metrics={}, asset_types={}, source_assets={}, relationships=0,
        evidence=0, dns_hostnames=0, dns_addresses=0, http_endpoints=0,
        http_hosts=0, technology_assets=0, technology_observations=0,
        dns_failures={}, http_failures=0, stages=[], external_adapter_metrics={},
    ))
finally:
    sys.stdout = original_stdout
    shutil.get_terminal_size = original_terminal_size

assert max(len(line) for line in output.getvalue().splitlines()) <= 60
assert "S H 4 Q" in SCAN_BANNER
assert max(len(line) for line in SCAN_BANNER.splitlines()) < 80
banner_lines = render_scan_banner(width=60).splitlines()
assert all(len(line) == 60 for line in banner_lines)
assert banner_lines[0].index("S H 4 Q") == (60 - len("S H 4 Q")) // 2
print("CLI narrow formatting test passed")
