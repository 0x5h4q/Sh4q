import io
import os
import shutil
import sys
from types import SimpleNamespace

from sh4q.cli.branding import SCAN_BANNER
from sh4q.cli.main import render_event_results, render_failure_results, render_scan_runs, render_technology_results


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
finally:
    sys.stdout = original_stdout
    shutil.get_terminal_size = original_terminal_size

assert max(len(line) for line in output.getvalue().splitlines()) <= 60
assert "████" in SCAN_BANNER
assert max(len(line) for line in SCAN_BANNER.splitlines()) < 80
print("CLI narrow formatting test passed")
