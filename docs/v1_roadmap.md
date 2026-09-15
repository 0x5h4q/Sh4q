# Sh4q Roadmap

This roadmap follows the current product state described in
[Current State and Maintainer Guide](current_state.md). Work is sequenced by
safety and operator value. Reviews may add notes, but they should not start
unrelated feature branches or silently reorder the roadmap.

## Completed Through v1.2.0

- Gate 1 initial-target authorization and Gate 2 discovery validation.
- Reserved/private-address controls, redirect authorization, and pinned native
  HTTP destinations.
- Durable events, evidence-first persistence, scan ownership, provenance,
  retries, interruption handling, and request/stage metrics.
- DNS, HTTP, certificate transparency, Subfinder, passive Amass, Wayback URL
  history, HTTPX enrichment, JavaScript extraction, bundle inspection, Katana,
  virtual-host discovery, and directory discovery.
- Results, scan overview, events, JSON/CSV/HTML exports, redaction, and scan
  diffs.
- Quiet/verbose output, JSONL progress, operator documentation, dependency
  controls, SQLite indexes/migrations, and packaging checks.
- Published GitHub release and tag `v1.2.0` with verified wheel installation.
- Versioned configuration schema with legacy v1 compatibility.

Katana, virtual-host discovery, directory discovery, and experimental Amass
remain explicit opt-ins. Their implementation does not make them suitable for
silent inclusion in a general profile.

## Current Milestone: Workflow Foundations

1. **Versioned configuration:** complete. New files declare
   `schema_version: 1`; incompatible versions fail before network activity.
2. **Scan templates:** next. Add named, reviewable recipes that disclose every
   enabled stage, required dependency, active/passive classification, and
   effective limit before execution.
3. **Repeatable comparisons:** persist the effective configuration/template,
   selected stages, and relevant tool versions with each scan so result changes
   can be separated from execution-setting changes.
4. **Proxy support:** define proxy behavior for native HTTP traffic and disclose
   which external adapters do or do not inherit it. Proxying must never bypass
   scope validation or destination authorization.
5. **Scheduled execution:** document or integrate repeatable cron/systemd jobs
   using stable templates and explicit output handling. A long-running Sh4q
   daemon is not required for the local v1 product.
6. **Inventory history:** expose useful first-seen and last-seen metadata in
   supported exports without confusing global asset history with scan ownership.

## Later Milestone: Platform v2

Only after the local workflow foundation is stable:

- API and dashboard;
- worker/job queue and scheduled jobs;
- PostgreSQL-backed shared deployment;
- authentication, RBAC, and audit controls;
- webhooks and integrations;
- richer historical and graph visualization.

Platform v2 is a separate product milestone, not an excuse to weaken the local
CLI's safety and evidence invariants.

## Ongoing Operations

- Restore GitHub Actions when the account/billing issue is resolved.
- Review pending Dependabot action upgrades after CI can execute again.
- Consider PyPI publication if it provides a clear distribution benefit.
- Measure large-scan storage/export behavior before adding more performance
  abstractions.
- Keep installation, limitations, and current-state documentation aligned with
  every release.

## Invariants For Every Milestone

- Gate 1 and Gate 2 remain mandatory.
- No out-of-scope observation becomes trusted inventory.
- Native contact occurs only after authorization.
- External-tool output remains untrusted until validated.
- Evidence, source ownership, and provenance remain reviewable.
- Execution is bounded by explicit time, output, candidate, and request limits.
- Shared behavior changes receive deterministic offline regression coverage.
- Active or higher-volume behavior is disclosed and explicitly selected.
