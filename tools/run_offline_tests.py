from __future__ import annotations

import argparse
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

OFFLINE_TESTS = (
    "test_adapter_contract.py",
    "test_adapter_execution_reporting.py",
    "test_adapter_output_pipeline.py",
    "test_adapter_runner.py",
    "test_async_dns_resolver.py",
    "test_cleanup_failure.py",
    "test_cli_sub_flag.py",
    "test_config_schema_version.py",
    "test_scan_template.py",
    "test_cli_formatting.py",
    "test_cli_presentation.py",
    "test_output_hierarchy.py",
    "test_ct_reporting.py",
    "test_discovered_dns_plugin.py",
    "test_discovered_name_sources.py",
    "test_host_list_mode.py",
    "test_name_composition.py",
    "test_discovered_http_plugin.py",
    "test_discovered_http_timeout.py",
    "test_event_bus.py",
    "test_event_failure.py",
    "test_event_inspection.py",
    "test_event_lifecycle.py",
    "test_event_retry.py",
    "test_export.py",
    "test_fingerprint_inputs.py",
    "test_fingerprint_output_pipeline.py",
    "test_http_reporting.py",
    "test_html_report.py",
    "test_javascript_extraction.py",
    "test_javascript_extraction_plugin.py",
    "test_javascript_extraction_pipeline.py",
    "test_javascript_stage_order.py",
    "test_katana_adapter.py",
    "test_katana_scheduler_integration.py",
    "test_documentation_qa.py",
    "test_dependencies.py",
    "test_dependency_identity.py",
    "test_httpx_fingerprint_adapter.py",
    "test_handler_presentation.py",
    "test_handler_registry.py",
    "test_idempotency.py",
    "test_native_fingerprints.py",
    "test_plugins.py",
    "test_request_limiter.py",
    "test_request_metrics_evidence.py",
    "test_results_query.py",
    "test_response_attributes.py",
    "test_scan_report.py",
    "test_scan_runs.py",
    "test_schema_version.py",
    "test_scope_engine.py",
    "test_storage_manual.py",
    "test_output_permissions.py",
    "test_dependency_bounds.py",
    "test_fingerprint_normalization.py",
    "test_httpx_fingerprint_plugin.py",
    "test_httpx_identity.py",
    "test_javascript_observation_sources.py",
    "test_vhost_discovery_plugin.py",
    "test_packaged_configs.py",
    "test_scan_runner_wiring.py",
    "test_probe_ports.py",
    "test_directory_discovery_plugin.py",
    "test_directory_candidate_loading.py",
    "test_directory_discovery_paths.py",
    "test_directory_persistence.py",
    "test_vhost_persistence.py",
    "test_vhost_request_accounting.py",
    "test_scope_manual.py",
    "test_scoped_http.py",
    "test_sqlite_concurrency.py",
    "test_stage_timing.py",
    "test_stage_metrics_evidence.py",
    "test_subfinder_adapter.py",
    "test_url_history_adapter.py",
    "test_url_history_pipeline.py",
    "test_scan_diff.py",
    "test_export_redaction.py",
    "test_url_history_scheduler_integration.py",
    "test_scheduler_progress.py",
    "test_subfinder_scheduler_integration.py",
    "test_trusted_service_http.py",
    "test_unique_scan_reporting.py",
)

OPTIONAL_INTEGRATION_TESTS = (
    "test_scoped_https_integration.py",
)

# Tests that contact real DNS resolvers, certificate-transparency providers,
# or live HTTP. They are excluded by design, not by oversight: the offline
# suite must stay deterministic and must not reach out to anyone. Run them
# deliberately with --network, and only against targets you are authorised to
# contact.
NETWORK_TESTS = (
    "test1.py",
    "test_crash.py",
    "test_dns.py",
    "test_dns_timing.py",
    "test_evidence.py",
    "test_integration.py",
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


def unlisted_tests() -> list[str]:
    """Test files in tests/ that no tuple above claims.

    A file that is in neither tuple never runs and nobody notices, which is
    how the suite once drifted to twenty unlisted files.
    """
    known = set(OFFLINE_TESTS) | set(OPTIONAL_INTEGRATION_TESTS) | set(NETWORK_TESTS)
    present = {path.name for path in (ROOT / "tests").glob("test*.py")}
    return sorted(present - known)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Sh4q's deterministic offline test suite")
    parser.add_argument("--include-integration", action="store_true")
    parser.add_argument(
        "--network",
        action="store_true",
        help="Also run tests that contact real DNS, CT providers, and live HTTP",
    )
    parser.add_argument("--match", help="Run tests whose filename contains this text")
    parser.add_argument("--timeout", type=float, default=90.0, help="Per-test timeout in seconds")
    parser.add_argument("--list", action="store_true", help="List selected tests without running them")
    args = parser.parse_args()

    selected = list(OFFLINE_TESTS)
    if args.include_integration:
        selected.extend(OPTIONAL_INTEGRATION_TESTS)
    if args.network:
        print("\n  Including network tests: these contact real DNS, CT providers,")
        print("  and live HTTP. Use only against targets you are authorised to reach.")
        selected.extend(NETWORK_TESTS)
    if args.match:
        selected = [name for name in selected if args.match.lower() in name.lower()]
    if args.list:
        print("\n".join(selected))
        return 0
    if not selected:
        parser.error("no tests matched the selection")

    print("\n  SH4Q OFFLINE TESTS")
    print("  ==================")
    unlisted = unlisted_tests()
    if unlisted:
        print("  WARNING: these test files are in no list and will never run:")
        for name in unlisted:
            print(f"    {name}")
        print()
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
    print(f"  Passed {passed}/{len(results)}   Failed {failed}   Duration {duration:.2f}s")
    if not args.network:
        print(f"  Skipped {len(NETWORK_TESTS)} network tests; run with --network to include them.")
    print()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
