# Sh4q Continuation Handoff

This file is the starting point for a new work thread. Read it together with
`architecture.md`, `docs/threat_model.md`, and `docs/limitations.md` before
making changes.

## Current Checkpoint

- Branch: `main`
- Release: `v0.1.0-alpha.36`
- Commit: documented by the latest release commit (`Bound discovery output`).
- Remote: `origin/main` and tag `v0.1.0-alpha.36` are published.
- Worktree should contain no intentional changes after the release commit.

Alpha.34 added `tests/test_amass_scheduler_integration.py`. It proves the
offline Amass process path through `ExternalAdapterPlugin`, Scheduler, EventBus,
Gate 2, evidence-first handling, and source ownership. The accepted names are
`api.example.com` and `portal.example.com`; `evil.test` is retained as evidence
but denied from the trusted graph.

## Verified Commands

The following executable tests passed before release:

```text
venv/bin/python tests/test_amass_scheduler_integration.py
venv/bin/python tests/test_amass_adapter.py
venv/bin/python tests/test_discovered_dns_plugin.py
venv/bin/python tests/test_subfinder_scheduler_integration.py
```

The repository-wide deterministic command remains:

```text
venv/bin/python tools/run_offline_tests.py
```

Alpha.35 replaces the block-art banner with a portable ASCII wordmark and keeps
the narrow-terminal formatting test green without escape warnings.

Alpha.36 bounds discovered-HTTP success output to ten representative lines,
retains every event and relationship in evidence/storage, and renders empty
HTTP exception messages as `unknown error`. The alpha.34 Amass scheduler test
and the new handler presentation test are now included in the offline runner.

## Next Work

The threat-model and limitations review and the core terminal presentation pass
are now documented. The next engineering milestone is a broader terminal audit:
consistent aligned tables for scan overviews and summaries, redirected-output
readability, and narrow-terminal verification across every command. After that,
implement HTML reporting using scan-owned data and
preserve the same provenance and evidence semantics.

Do not begin another live target scan as a substitute for these milestones.
Do not add active scanners or broaden claims about liveness, completeness, or
vulnerability verification without a documented policy decision and offline
regression coverage.

## Suggested First Inspection

1. `architecture.md` sections “Gate 4: Engineering quality” and “Delivery Plan”.
2. `docs/threat_model.md` and `docs/limitations.md`.
3. `sh4q/cli/main.py` and `sh4q/cli/branding.py` for terminal output paths.
4. `tests/test_cli_formatting.py`, `tests/test_results_query.py`, and the
   offline test runner before changing presentation behavior.
