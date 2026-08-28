# sh4q Architecture and Product Direction

## Direction

sh4q is being developed as a safety-first reconnaissance control plane, not as a feature-for-feature replacement for reconFTW. Its value is coordinating discovery tools while enforcing scope, preserving provenance, surviving interruption, and producing reviewable evidence.

The project must not advertise itself as “trustworthy” or “scope-enforced” until the controls below are implemented and covered by regression tests. The current redirect behavior is a release blocker: an HTTP request can follow a redirect to an unauthorized host before the discovery handler performs its post-request check.

## Core Invariants

Every outbound operation must satisfy all of these conditions before it occurs:

1. The destination matches the configured scope and exclusions.
2. The destination’s resolved IP is allowed; private, loopback, link-local, multicast, and otherwise reserved addresses are denied unless explicitly supported by policy.
3. The port and request are admitted by the rate, concurrency, and total-budget controls.
4. Redirects are validated one hop at a time. No client may automatically follow an unvalidated redirect.
5. The operation and its decision are recorded with source plugin, target, timestamp, and tool/version context.

Discovery validation and request accounting are separate concerns. A scope policy answers “may this destination be contacted?” A limiter answers “may this request run now?” Asset discovery must not consume network budget merely because it is being validated.

## Target Architecture

The existing package boundaries remain useful, but network access should move behind shared services:

- `scope/`: normalized hostname/IP/port policy and explicit allow/deny decisions.
- `network/` (new): scoped DNS resolution, HTTP client, redirect handling, private-IP checks, and request admission.
- `limits/` (new or folded into `network/`): semaphore, requests-per-second limiter, and request budget.
- `plugins/`: discovery logic; plugins request operations through scoped services rather than constructing unrestricted clients.
- `events/`: durable event state machine with retry count, failure/dead-letter state, and graceful shutdown.
- `storage/`: transactional SQLite repositories, WAL/busy-timeout configuration, schema versioning, nodes, relationships, evidence, and provenance.
- `application/`: scan lifecycle, recovery, reporting, and CLI orchestration.

External tools should be added through a subprocess adapter that uses argument arrays (never shell strings), timeouts, output limits, sanitized environments, exit-status handling, and captured tool versions.

Discoveries should distinguish confidence states such as `DISCOVERED`, `RESOLVED`, `REACHABLE`, and `VERIFIED`; a certificate record is not evidence that a host is live.

## Required Remediation and Test Gates

### Gate 1: Safety boundary

- Disable automatic HTTP redirects.
- Validate every redirect destination before following it.
- Resolve and validate destination IPs, including DNS rebinding protection.
- Normalize lowercase/trailing-dot/IDNA hostnames.
- Enforce allowed ports and deny reserved address ranges by default.

Tests must use local fake DNS/HTTP servers and assert that unauthorized redirects, rebinding, ports, and reserved IPs are never contacted.

### Gate 1 Exit Review (2026-08-26)

Implemented and regression-tested: initial target authorization; hostname normalization; port checks; reserved/private-address policy; hop-by-hop redirect validation; approved-IP connection pinning; original Host/TLS identity preservation; multi-address fallback; trusted CT service host policy; redirect denial for trusted services; URL canonicalisation; and CT partial-result preservation.

Gate 1 is **functionally complete for the current DNS, HTTP, and CT paths**, but not a claim of production hardening. Before release, retain these follow-up issues:

- add explicit boundary tests for malformed URLs, redirect loops, denied ports, resolution failures, and all supported IPv4/IPv6 edge cases;
- verify IP pinning against supported HTTPX versions and a local multi-host TLS setup;
- route any future network-capable plugin through the same service boundary;
- ~~replace stage-interleaved console output with ordered stage summaries~~ (implemented: scheduler drains each plugin stage before continuing);
- expose per-probe diagnostics in the final report;
- extend Gate 3 metrics and reporting as new network-capable adapters are added;
- review provider/API exceptions and private-address development mode.

These are tracked follow-ups, not permission to expand scope or add active scanners before Gate 2 reliability work is complete.

### Deferred Reliability Enhancements

- **Ordered stage reporting:** the asynchronous Event Bus can print DNS, HTTP, and CT handler output after the Scheduler has started the next plugin. Add stage-completion boundaries or buffered presentation so terminal output follows scan order while event processing remains asynchronous.
- **Plugin-attempt persistence:** Ctrl+C currently preserves already-published discovery events, but an interrupted network call is rerun from the beginning on the next scan. A future `scan_run`/`plugin_run` record should track plugin attempts, start/completion state, cancellation, and resumability. This is a later reliability enhancement, not a reason to weaken event recovery or publish partially trusted state.
- **CT result persistence:** successful CT names are currently retained in the graph/evidence for the run, while in-memory provider caching ends when the CLI exits. A future provider-observation table should distinguish new names, previously known names, and provider unavailability across separate scans.
- **Event attempt terminology:** event-log `attempts` counts handler failures only; it does not count Scheduler plugin executions. The CLI now labels the field as event attempts. A future `plugin_run` record should expose plugin attempts separately.
- **Event target filtering:** `sh4q events --target <hostname>` now filters durable records by their `scan_target` payload.

### Gate 2: Reliability

- Make event dispatch exception-safe; always call `task_done()`.
- Preserve failed events for retry or dead-letter handling.
- Add graceful cancellation and shutdown.
- Isolate plugin cleanup failures.
- Add crash/recovery tests for handler failure, duplicate delivery, and restart.

Preliminary SQLite concurrency validation (2026-08-26): 50 parallel synthetic work units completed without observed lock errors or lost records, producing 100 nodes, 50 relationships, 50 durable events, and 50 evidence rows in approximately 0.669 seconds. The thesis evaluation must repeat this test several times and report the mean, median, minimum, maximum, and standard deviation; the single run is not a formal benchmark.

### Gate 3: Enforced controls

- Implement configured concurrency, request-rate, and total-request limits.
- Define and test whether retries consume budget.
- Add metrics for admitted, denied, retried, and blocked requests.

### Gate 3 Progress (2026-08-26)

The configured concurrency, requests-per-second, and total-request budget are now enforced by one scan-wide `RequestLimiter` shared by target HTTP and trusted CT clients. Every real HTTP transport attempt consumes budget, including redirect hops, fallback-IP attempts, CT pagination, and later plugin retries. Scope or address-policy denial consumes no request budget because no transport contact occurs. Cancellation while waiting for admission refunds the reserved budget unit.

The scan summary reports admitted, budget-denied, completed, failed, and peak-concurrency counts. Deterministic fake-transport tests verify the concurrency ceiling, pacing, budget exhaustion before transport contact, fallback-attempt accounting, metrics, and zero budget use for denied scope. Gate 3 remains open until retry/blocked terminology is fully represented in durable metrics and adapter contracts prevent future tools from bypassing admission.

Each completed or interrupted scan now also writes a `request_metrics` evidence record containing the configured limits, observed counters, peak concurrency, duration, and outcome. This preserves the summary for later audit without introducing the deferred `scan_run` schema prematurely.

The first adapter contract is now defined in `sh4q/adapters/`. Future external tools receive an `AdapterContext` containing the scope engine and controlled output directory, and must construct an argument array rather than a shell string. The native request limiter is deliberately not exposed as a claimed control over opaque subprocess traffic: it cannot govern packets generated inside another program. Real adapters require tool-specific restrictions and, for strong packet-level guarantees, later OS-level containment.

The controlled runner is now implemented in `sh4q/adapters/runner.py`. It launches only allow-listed executables without a shell, uses a reduced environment, bounds stdout/stderr while the process is running, kills the process group on timeout/cancellation/output overflow, and exposes a version probe. It returns structured results but does not itself authorise discovered assets; adapters must still validate and persist outputs through the normal Gate 2 path.

The generic `ExternalAdapterPlugin` now connects controlled execution to durable evidence and Gate 2. It records the secret-redacted command, adapter/tool versions, exit code, duration, timeout/output-limit state, stdout, and stderr. Parsed discoveries then follow the existing evidence-first handler: every observation is retained, while an out-of-scope hostname is denied before asset or relationship storage. A deterministic fake adapter proves this behavior without contacting an external service.

The first concrete adapter is `SubfinderAdapter`. It is intentionally passive: it invokes only `subfinder -silent -d <target>`, parses newline-delimited hostnames, removes duplicates, and redacts the target in execution evidence. It is disabled by default and enabled explicitly with `sh4q scan <target> --sub`. Sh4q resolves and allow-lists the installed binary, provides an isolated adapter home, and validates output through Gate 2. The offline scheduler integration test proves Gate 1, controlled execution, event completion, evidence-first handling, deduplication, and out-of-scope denial without network access. Subfinder's provider traffic remains outside Python-level request accounting.

A live authorised `--sub` run returned 884 Subfinder hostname observations alongside 186 CT names. This exposed a reporting defect: counters increased for every accepted observation even when SQLite rejected an already-existing relationship, and overlapping CT/Subfinder names inflated the total. Reporting now tracks unique asset and relationship identifiers per scan while retaining separate per-source counts and all raw evidence. Subfinder hostnames remain discoveries, not claims that the hosts resolve or serve live applications.

The discovered-DNS stage is now an explicit passive phase after Subfinder. It scope-checks each hostname before resolver contact, resolves approved names with bounded concurrency, preserves resolution failures, and applies reserved-address policy before storing IP assets. This ordering matters: an out-of-scope name must not be resolved merely because it was emitted by a tool. Discovered HTTP probing remains a separate future opt-in phase.

A live `--sub` run showed that resolving hundreds of names as one scheduler batch could hit the stage deadline, trigger three whole-batch retries, take over eight minutes, and lose partial results. The resolver now applies a per-name timeout, bounded concurrency, and cancellation-safe partial-result handling; output is capped to a compact sample while full DNS evidence remains durable. This incident and correction are retained as a reliability finding.

A subsequent run reported zero adapter names because Subfinder was terminated at the original 30-second process limit; durable evidence showed `timed_out=true` and return code `-15`. Adapter failures are now printed explicitly instead of appearing as successful zero-result stages, the passive Subfinder allowance is 120 seconds, and discovered-DNS accepts hand-off data only from the Subfinder stage so later empty stages cannot erase its input.

The large-run report now separates evidence produced in the current scan from historical evidence retained in the database, labels request counters as native HTTP/CT metrics (not Subfinder's opaque provider traffic), and reports discovered-DNS failures alongside resolved names. These distinctions prevent cumulative storage and external-tool activity from being mistaken for current-scan performance.

Non-SQL usability has begun with `sh4q results`: users can list domains, URLs, target-filtered failures, and IPs related through `RESOLVES_TO` without writing SQL. `--target` uses exact-domain/subdomain boundaries and now filters assets instead of being silently ignored. Results remain historical target views until `scan_run` ownership is implemented; accurate `--latest` and per-scan views must not be faked from timestamps. JSON/CSV exports and an HTML report remain later work. SQLite remains the source of record.

First-class scan identity has begun with a durable `scan_runs` table and `sh4q scans`. New executions receive a unique run ID and transition from `RUNNING` to `COMPLETED` or `INTERRUPTED`. Historical scans created before this migration cannot be reconstructed reliably and therefore do not receive invented IDs. Evidence, events, and asset observations still need explicit run ownership before exact `results --scan` views are enabled.

New evidence and accepted asset relationships now carry scan ownership through `scan_run_id` and the `scan_assets` observation table. The global graph remains deduplicated, while per-scan observations remain queryable. Scan summaries print the run ID, and users can request `sh4q results --scan <id>` or `sh4q results --latest` (optionally with `--target`). Pre-migration data remains available through historical target views but cannot appear in exact run views.

The first live validation of this migration exposed a handler defect: the asset-recording helper referenced `scan_run_id` outside its scope. Accepted assets were counted in memory, but ownership rows were not written, so `results --latest` showed zero assets and export correctly refused the run. The helper now receives the run ID explicitly and persists ownership before updating counters. A regression test verifies successful ownership, out-of-scope rejection, and counter consistency when persistence fails. The affected run is intentionally not backfilled because exact ownership cannot be reconstructed safely.

Scan-specific JSON and CSV export is now available through `sh4q export`. Export requires `--scan` or `--latest`, reads the complete scan-owned asset set without the interactive display limit, includes source-plugin provenance, and refuses to overwrite an existing file unless `--force` is supplied. HTML reporting remains future Gate 4 work.

Export also supports `--alive http`, which returns only scan-owned domain assets that have a corresponding scan-owned `SERVES` relationship to an observed URL. This is deliberately an evidence-backed HTTP liveness definition; CT or Subfinder discovery alone is not labelled alive.
Alive exports now include the observed endpoint and HTTP status (`endpoint` and `http_status` in CSV; endpoint metadata in JSON), making the liveness classification directly auditable.
The same interface supports `--alive dns`, which exports one row per domain and permitted resolved address from scan-owned `RESOLVES_TO` relationships (`resolved_address` in CSV).

Live validation exposed two details in this filter: HTTP observations own the URL endpoint and its `SERVES` relationship rather than separately owning the source domain node, and a legitimate empty filtered result must not be mistaken for missing scan ownership. The query now derives responding domains from scan-owned `SERVES` relationships and performs migration detection against the unfiltered ownership count.

Migration-era scans can contain scan-owned evidence but no `scan_assets` observations. Export now reports this condition explicitly rather than producing a misleading empty file. `--latest` selects the latest completed run, while `sh4q scans` continues to expose unfinished `RUNNING` records for audit and recovery.

Adapter breadth remains intentionally one tool: Subfinder proves the external-tool contract, execution evidence, Gate 2 output validation, and discovered-DNS hand-off. The next passive adapter should be added after scan ownership and result export are stable, so it reuses a proven contract rather than introducing another parallel data path.

Target filtering is applied before the result limit. An early implementation limited the global node table first and then filtered in Python, causing the same target query to return 73 rows at limit 100 and 116 at limit 200. Domain filtering now occurs in SQL and URL filtering applies its limit only after hostname matching, so `--limit` consistently means matching results.

Product end goal: Sh4q is a policy and evidence control plane for authorised attack-surface discovery. It coordinates specialised tools, prevents out-of-scope findings from becoming trusted assets, records what each tool actually observed, and produces a reproducible inventory that security teams can review. For a mobile-application-security practitioner, the same model could later govern an organisation's domains, APIs, certificate names, cloud endpoints, and mobile backend hosts without treating every tool result as automatically trustworthy.

### Technology and Readiness Decision (2026-08-27)

Python remains the implementation language for the academic project and MVP. It is adequate for the present asynchronous I/O workload and provides rapid development through asyncio, HTTPX, Pydantic, SQLite support, and the security-tool ecosystem. Go would improve single-binary distribution, memory use, compile-time checking, and high-concurrency service deployment, but would not automatically correct scope, redirect, evidence, retry, or adapter-design defects. Rewriting now would require revalidating every safety and reliability guarantee without evidence that Python is the limiting factor. A Go worker or rewrite should be considered only after profiling a stable specification demonstrates a real runtime or distribution constraint.

Current readiness is: strong academic/MVP architecture, credible but early orchestration core, and a public research prototype rather than a production reconFTW replacement. A credible public MVP still requires the controlled adapter runner, deterministic standard tests, CI, threat model, limitations, durable scan/plugin identities, and repeated evaluation. These decisions and their evidence must remain understandable enough for the author to defend orally; documentation should explain not only what was built, but why each boundary and trade-off exists.

### Gate 4: Engineering quality

- Replace print-only tests with assertions and deterministic fakes.
- Add CI for supported Python versions, linting, type checking, and offline tests.
- Add SQLite transactions, WAL, busy timeout, and migration/version checks.
- Document threat model, plugin contract, configuration, and known limitations.

## Delivery Plan

Work in small, reviewable increments. Each increment must add regression tests before expanding discovery breadth. Do not add active scanners until the safety boundary and event guarantees pass their gates.

## Realistic Timeline

For one motivated developer working part-time (8–12 hours/week):

- **2–4 weeks:** redirect/IP safety boundary, hostname normalization, and regression tests.
- **2–3 weeks:** durable event failure handling, shutdown, retries, and recovery tests.
- **2–3 weeks:** real rate/concurrency/budget controls and metrics.
- **3–5 weeks:** storage hardening, schema versioning, CI, documentation, and CLI/reporting cleanup.
- **4–8 weeks:** first high-quality external-tool adapter and integration tests.
- **2–4 months afterward:** additional adapters, scheduling, exports, and usability improvements.

A credible, defensible beta could therefore take roughly **3–5 months part-time**. A substantial product with several maintained adapters, polished reporting, and operational documentation is more realistically **6–12 months**. These estimates assume disciplined scope; attempting to match reconFTW’s breadth would extend the project indefinitely.

## Release Positioning

Before the safety gates pass, describe sh4q as an experimental orchestration framework. Afterward, advertise the narrower and defensible claim: **policy-controlled, resumable reconnaissance orchestration with evidence provenance**. Publish limitations and a threat model alongside benchmarks; credibility is part of the product.

## Academic Research Records

The academic project is maintained separately from this engineering record. Source discovery follows `docs/research_workflow.md`: OpenAlex/Crossref may collect candidate metadata, but Zotero and publisher/library verification determine what can be cited. Search manifests, literature matrices, and claim-to-source notes should be retained as reproducibility evidence.
