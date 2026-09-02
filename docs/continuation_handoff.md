# Sh4q Continuation Handoff

This file is the starting point for a new work thread. Read it together with
`architecture.md`, `docs/threat_model.md`, and `docs/limitations.md` before
making changes.

## Current Checkpoint

- Branch: `main`
- Release: `v0.1.0-alpha.51` plus post-alpha v1 hardening commits.
- Commit: `1925c83` (`Record packaging validation for v1`).
- Remote: `origin/main` is pushed at `1925c83`; tag `v0.1.0-alpha.51` remains the latest published tag.
- Untracked user files `tesla.html` and `tyler.html` are intentionally preserved.

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

Alpha.46 makes HTML technology rows endpoint-aware and labels the status filter
as HTTP status, addressing ambiguity seen in browser screenshots. A clipped
wordmark in a screenshot taken after scrolling is expected browser behavior.

The generated HTML was checked against the real 1,510-asset scan and passes
structural QA: all filters and reset control are present, the embedded script
has no network calls, and the report is self-contained. This environment lacks
a browser/Playwright runtime, so pixel-level desktop/mobile verification remains
an explicit release-QA task.

Alpha.48 embeds the repository `banner.png` in exported HTML reports as a data
URI with responsive header sizing and an accessible `SH4Q` fallback. Reports
remain portable without adjacent asset files.

Alpha.49 completes the next terminal-audit slice: long targets, scan IDs,
timestamps, and database paths in scan summaries and persisted overviews are
bounded on narrow terminals. Redirected output retains the full values.

Alpha.50 updates the HTML report hero to center `banner.png` as the dominant
brand visual, places scan identity beneath it, and prevents long domains/URLs
from wrapping character-by-character in the asset table. Structural HTML QA and
real-data export pass; browser screenshot verification still requires a browser
runtime unavailable in this environment.

Alpha.51 enlarges the centered banner hero and makes empty/non-applicable table
fields explicit with `-`; empty filter results now have a clear table message.
The real 1,510-asset HTML export and fixture pass.

The narrow-terminal audit remains green (`tests/test_cli_formatting.py`). A
full offline run is currently blocked by this environment's async SQLite path:
`aiosqlite.connect(':memory:')` stalls under both CPython 3.14.4 and the
Python 3.12 control environment, while synchronous SQLite succeeds. This is
not isolated to one Python minor version or aiosqlite release. Full-suite and
concurrency timings must be rerun in a known-good environment before a v1
readiness claim.

Compatibility checks also reproduced the hang with aiosqlite `0.20.0` and
`0.21.0`; downgrading the dependency is not a workaround. The environment was
restored to `0.22.1`. The package metadata remains open to Python 3.14, but
3.14 support is experimental until a working runtime is verified.

On the user's Python 3.12 environment, the complete offline suite passed
`43/43` in `23.50s`. Five consecutive SQLite concurrency runs also passed with
durations of `0.869s`, `0.971s`, `0.676s`, `0.573s`, and `0.576s` (mean
`0.733s`, median `0.676s`, min `0.573s`, max `0.971s`). This confirms the
storage path is reliable on a normal supported runtime.

Packaging QA also passed: a wheel was built, installed into a fresh Python
3.12 environment, and `sh4q --help` completed successfully. The wheel includes
the report assets required by the HTML export. A rebuilt wheel now explicitly
contains `sh4q/assets/banner.png`; a fresh install embeds the banner in reports.

Chromium verification passed at desktop (`1440x1000`) and mobile (`390x844`)
viewports. The hero rendered, all five filters populated, no page-level
horizontal overflow occurred, and search/reset interaction changed counts from
`19 of 1510` back to `1510 of 1510`.

The transparent replacement `banner.png` is rendered at a larger responsive
size on a light full-width hero surface so the dark logo remains readable. The
HTML fixture passes with the updated sizing.

The Amass enumeration command itself can stall after a successful version probe
(observed with the installed `/usr/bin/amass`). Its opt-in process ceiling is
now 45 seconds, so future scans record the timeout and continue without the
previous 180-second delay.

## Next Work

The next milestone is to run the complete offline suite under Python 3.13,
repeat SQLite concurrency/recovery tests, and record timing statistics. Then run
browser-level desktop/mobile verification with Chromium/Playwright, apply any
visual polish, perform packaging/install QA, and complete the v1 threat-model
and authorized-domain acceptance review. Do not claim pixel-level browser
verification in an environment without a browser runtime.

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
