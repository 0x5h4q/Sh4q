from __future__ import annotations

import argparse
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

OFFLINE_TESTS = (
    "test_amass_adapter.py",
    "test_adapter_contract.py",
    "test_adapter_execution_reporting.py",
    "test_adapter_output_pipeline.py",
    "test_adapter_runner.py",
    "test_async_dns_resolver.py",
    "test_cleanup_failure.py",
    "test_cli_sub_flag.py",
    "test_cli_formatting.py",
    "test_ct_reporting.py",
    "test_discovered_dns_plugin.py",
    "test_discovered_http_plugin.py",
    "test_event_bus.py",
    "test_event_failure.py",
    "test_event_inspection.py",
    "test_event_lifecycle.py",
    "test_event_retry.py",
    "test_export.py",
    "test_fingerprint_inputs.py",
    "test_fingerprint_output_pipeline.py",
    "test_http_reporting.py",
    "test_httpx_fingerprint_adapter.py",
    "test_idempotency.py",
    "test_native_fingerprints.py",
    "test_plugins.py",
    "test_request_limiter.py",
    "test_request_metrics_evidence.py",
    "test_results_query.py",
    "test_scan_report.py",
    "test_scan_runs.py",
    "test_schema_version.py",
    "test_scoped_http.py",
    "test_sqlite_concurrency.py",
    "test_stage_timing.py",
    "test_stage_metrics_evidence.py",
    "test_subfinder_adapter.py",
    "test_subfinder_scheduler_integration.py",
    "test_trusted_service_http.py",
    "test_unique_scan_reporting.py",
)

OPTIONAL_INTEGRATION_TESTS = (
    "test_scoped_https_integration.py",
)


@dataclass(frozen=True)
class TestResult:
    name: str
    status: str
    duration: float
    output: str


def _fit(value: str, width: int) -> str:
    return value if len(value) <= width else value[: width - 3] + "..."


def run_test(name: str, timeout: float) -> TestResult:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tests" / name)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        status = "PASS" if completed.returncode == 0 else "FAIL"
        output = completed.stdout.strip()
    except subprocess.TimeoutExpired as error:
        status = "TIMEOUT"
        retained = error.stdout or ""
        output = retained.decode() if isinstance(retained, bytes) else retained
        output = output.strip()
    return TestResult(name, status, time.monotonic() - started, output)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Sh4q's deterministic offline test suite")
    parser.add_argument("--include-integration", action="store_true")
    parser.add_argument("--match", help="Run tests whose filename contains this text")
    parser.add_argument("--timeout", type=float, default=90.0, help="Per-test timeout in seconds")
    parser.add_argument("--list", action="store_true", help="List selected tests without running them")
    args = parser.parse_args()

    selected = list(OFFLINE_TESTS)
    if args.include_integration:
        selected.extend(OPTIONAL_INTEGRATION_TESTS)
    if args.match:
        selected = [name for name in selected if args.match.lower() in name.lower()]
    if args.list:
        print("\n".join(selected))
        return 0
    if not selected:
        parser.error("no tests matched the selection")

    print("\n  SH4Q OFFLINE TESTS")
    print("  ==================")
    results = []
    for name in selected:
        result = run_test(name, max(1.0, args.timeout))
        results.append(result)
        print(f"  {result.status:<7} {_fit(name, 46):<46} {result.duration:>7.2f}s")
        if result.status != "PASS" and result.output:
            for line in result.output.splitlines()[-20:]:
                print(f"           {line}")

    passed = sum(result.status == "PASS" for result in results)
    failed = len(results) - passed
    duration = sum(result.duration for result in results)
    print("  " + "-" * 64)
    print(f"  Passed {passed}/{len(results)}   Failed {failed}   Duration {duration:.2f}s\n")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
