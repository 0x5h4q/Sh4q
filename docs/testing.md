# Testing Sh4q

## Deterministic Offline Suite

Run the repository's deterministic offline suite:

```bash
venv/bin/python tools/run_offline_tests.py
```

The runner executes an explicit allow-list of tests, prints one aligned result row per script, captures failure output, enforces a per-test timeout, and exits nonzero if any test fails.

Useful options:

```bash
venv/bin/python tools/run_offline_tests.py --list
venv/bin/python tools/run_offline_tests.py --match fingerprint
venv/bin/python tools/run_offline_tests.py --include-integration
venv/bin/python tools/run_offline_tests.py --network
```

Every file in `tests/` belongs to exactly one list in the runner:
`OFFLINE_TESTS` runs by default, `OPTIONAL_INTEGRATION_TESTS` runs under
`--include-integration`, and `NETWORK_TESTS` runs under `--network`. Those six
contact real DNS resolvers, certificate-transparency providers, and live HTTP,
so run them deliberately and only against targets you are authorised to reach.

A file in none of the three lists never runs. The runner now prints a warning
naming any such file, because the suite once drifted to twenty unlisted tests
without anything noticing.

The default suite uses fakes, temporary SQLite databases, controlled subprocesses, and mock transports. It does not require Subfinder or access to public DNS, HTTP, or certificate-transparency providers.

Two of its checks exist because a green suite once hid a real defect, and are
worth keeping in mind when adding stages:

- `test_scope_engine.py` asserts the authorization perimeter itself -- both
  gates, address policy, and normalization. Before it existed, nothing in the
  suite failed if scope enforcement regressed.
- `test_scan_runner_wiring.py` builds the plugin chain for every stage
  combination against a scope that denies at Gate 1, so no packet is sent. It
  exists because stages were tested individually while the `if include_x:`
  chain that assembles them was not, and a stage wired into the wrong branch
  passed every test while crashing the CLI.

## Optional Integration Checks

`--include-integration` adds local integration checks that may require operating-system facilities such as OpenSSL and loopback socket binding. These checks still do not contact a public target.

The workflow is configured for CI, but GitHub Actions is currently disabled due
to the repository owner's billing issue. Run the suite locally before merging.
Live checks and manual engineering scripts remain outside the offline suite.
They must be run deliberately and documented with the target authorization,
network conditions, tool versions, and exact Git commit.

## Interpreting Test Results

The offline suite is the repeatable pass/fail check for the project. Optional integration checks exercise local operating-system and TLS behaviour. Live-domain checks are demonstrations only: results depend on the network, DNS resolver, provider availability, rate limits, and target responses, so a live failure is not by itself proof of a Sh4q defect.
