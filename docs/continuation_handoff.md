# Sh4q Continuation Handoff

This file is the starting point for a new work thread. Read it together with
`architecture.md`, `docs/threat_model.md`, and `docs/limitations.md` before
making changes.

## Current Checkpoint

- Branch: `main`
- Release: `v0.1.0-alpha.37`
- Commit: documented by the latest release commit (`Center SH4Q terminal banner`).
- Remote: `origin/main` and tag `v0.1.0-alpha.37` are published.
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

Alpha.37 replaces the ambiguous font-style banner with an explicit `S H 4 Q`
wordmark centered to the active terminal width, including narrow-terminal
coverage.

The v1 roadmap and outreach pitch are now documented in `docs/v1_roadmap.md`
and `docs/pitch.md`. The v1 adapter policy keeps the current proven set and
defers active scanners; a passive URL-history adapter is only a post-v1
candidate until its policy and provenance tests exist.

The HTML report is now implemented behind `sh4q export --format html`. It
embeds scan-owned assets and provides offline client-side filters for asset
type, host, status, technology/category, source, and text search. It also
includes failure details, stage timings, native request metrics, and an
evidence index. Remaining work is visual/browser polish and final release QA.

Alpha.41 makes external adapter version probing a preflight gate. A hanging
version probe records a timed-out adapter execution and skips enumeration, so a
broken Amass binary cannot consume its full 180-second process budget. The
offline adapter pipeline and runner tests cover this behavior.

Alpha.43 refines the HTML report layout: controls no longer overlap at desktop
widths, cards and tables have a restrained hierarchy, mobile spacing is covered,
and a reset-filters action is available. Browser screenshot verification remains
the next QA task.

Alpha.44 prevents whole-batch retries for discovered HTTP when its stage times
out. Completed per-host results are preserved during cancellation, and the
scheduler reports retries as disabled for this enrichment stage. This avoids
repeating hundreds of probes after a budget or stage-timeout event.

Alpha.45 normalizes blank HTTP transport exceptions to a useful class-based
diagnostic instead of emitting repeated `unknown error` lines.

The Amass enumeration command itself can stall after a successful version probe
(observed with the installed `/usr/bin/amass`). Its opt-in process ceiling is
now 45 seconds, so future scans record the timeout and continue without the
previous 180-second delay.

## Next Work

The threat-model and limitations review, first terminal presentation pass, core
HTML report, adapter fail-fast handling, and discovered-HTTP timeout policy are
now documented. The next engineering milestone is browser
verification and visual polish, then the broader terminal audit:
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
