# Testing Sh4q

## Deterministic Offline Suite

Run the same suite used by continuous integration:

```bash
venv/bin/python tools/run_offline_tests.py
```

The runner executes an explicit allow-list of tests, prints one aligned result row per script, captures failure output, enforces a per-test timeout, and exits nonzero if any test fails.

Useful options:

```bash
venv/bin/python tools/run_offline_tests.py --list
venv/bin/python tools/run_offline_tests.py --match fingerprint
venv/bin/python tools/run_offline_tests.py --include-integration
```

The default suite uses fakes, temporary SQLite databases, controlled subprocesses, and mock transports. It does not require Subfinder or access to public DNS, HTTP, or certificate-transparency providers.

## Optional Integration Checks

`--include-integration` adds local integration checks that may require operating-system facilities such as OpenSSL and loopback socket binding. These checks still do not contact a public target.

Live checks and manual engineering scripts remain outside CI. They must be run deliberately and documented with the target authorization, network conditions, tool versions, and exact Git commit.

## Current Exclusions

Older manual or live-oriented scripts such as `test_dns.py`, `test_evidence.py`, `test_integration.py`, `test_scope_manual.py`, and `test_storage_manual.py` are not authoritative pass/fail checks. They should be converted to deterministic assertion-based tests or retained explicitly as demonstrations before private-alpha release.
