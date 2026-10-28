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
- DNS, HTTP, certificate transparency, Subfinder, Wayback URL
  history, HTTPX enrichment, JavaScript extraction, bundle inspection, Katana,
  virtual-host discovery, and directory discovery.
- Results, scan overview, events, JSON/CSV/HTML exports, redaction, and scan
  diffs.
- Quiet/verbose output, JSONL progress, operator documentation, dependency
  controls, SQLite indexes/migrations, and packaging checks.
- Published GitHub release and tag `v1.2.0` with verified wheel installation.
- Versioned configuration schema with legacy v1 compatibility.

## Completed in v1.4.0

- Two Gate 2 fixes: `dns_resolution` authorizes its hostname under the scope
  handling the event, closing a bypass reachable through durable event
  recovery; and `scope.ports` gates inventory as well as contact.
- The authorization perimeter refuses strings that cannot name a host, so
  subdomain inheritance is no longer granted to `.example.com` or
  `*.example.com`, and a malformed target entry matches nothing.
- A third-party disclosure ledger in observed and declared tiers, with every
  scan stating what it is about to disclose before it does.
- `crt.name` as a default certificate-transparency source alongside
  certspotter and crt.sh, with `certificate_transparency.sources` to declare
  (and narrow) which parties a scan contacts.
- Configurable enrichment bounds, with stage deadlines derived from them
  rather than flat.
- Every listing states its denominator; a requested `--limit` is honoured
  rather than silently clamped; a stage cut off at its deadline keeps its work
  and records that it was cut off.
- `--redact` reports what it rewrote and reaches every URL-bearing field.
- The offline suite runs 99 tests, up from 77 at v1.3.0, with every file
  accounted for.

## Completed in v1.3.0

- Named scan templates: versioned recipes that own stage selection, validate
  their stage list and candidate files, and refuse conflicting flags.
- Every authorized port probed, rather than only the well-known pair.
- Gate 2 parent-domain authorization, virtual-host request accounting, and
  virtual-host port correctness.
- Directory classification against a generated not-found baseline.
- The Amass adapter retired; Subfinder covers passive subdomain discovery.
- Finding-oriented terminal output, with colour limited to interactive use.
- Perimeter, wiring, packaged-config, and port regression coverage; the
  offline suite ran 77 tests at that release, with every file accounted for.
- A documented release process in `RELEASING.md`.

Katana, virtual-host discovery, and directory discovery
remain explicit opt-ins. Their implementation does not make them suitable for
silent inclusion in a general profile.

## Current Milestone: Workflow Foundations

1. **Versioned configuration:** complete. New files declare
   `schema_version: 1`; incompatible versions fail before network activity.
2. **Scan templates:** the recipe itself is complete and shipped in v1.3.0.
   Stage disclosure is complete: before every scan, Sh4q prints per-stage risk
   level, required external tool, PATH status, and effective bound.
   `--dry-run` performs Gate 1, prints the resolved scope, stage plan, request
   budget, and planned third-party disclosures, then exits without a network
   request.
3. **Repeatable comparisons:** persist the effective configuration/template,
   selected stages, and relevant tool versions with each scan so result changes
   can be separated from execution-setting changes.
4. **Proxy support:** define proxy behavior for native HTTP traffic and disclose
   which external adapters do or do not inherit it. Proxying must never bypass
   scope validation or destination authorization. Two constraints found while
   specifying it: `ScopedHTTPClient` passes an explicit `transport=`, and httpx
   does not consult `proxy=` when one is given, so the proxy must be threaded
   into the pinned transport or the setting is silently ignored. And IP pinning
   needs local DNS while proxying for privacy needs remote DNS, so these are
   two features with opposite requirements, not one.
4a. **Third-party disclosure:** shipped in v1.4.0. `results --disclosures`
   reports which external services learned about a target, in observed and
   declared tiers, and every scan states what it is about to disclose before
   it does. Remaining: no custom `User-Agent`, so authorised traffic is not
   identifiable as authorised.
5. **Scheduled execution:** document or integrate repeatable cron/systemd jobs
   using stable templates and explicit output handling. A long-running Sh4q
   daemon is not required for the local v1 product.
6. **Inventory history:** shipped in this cycle. `results --history` exposes
   graph-wide first-seen and last-seen timestamps, marks scan-owned assets as
   `new` or `returning`, and JSON/CSV/HTML exports carry both timestamps
   without conflating global asset history with per-scan ownership.

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

## Future Capability: Challenge-Aware Response Classification (design note)

This is **not** on the current core roadmap. It is recorded here so the idea is
not lost, and it should be revisited only after the execution-identity and
read-seam milestones are complete.

**Name:** Challenge-Aware Response Classification — not `cloudflare-skip` or any
automatic bypass flag.

**First version would:**
- Identify likely WAF/challenge responses and distinguish them from ordinary
  application denials;
- Preserve the evidence and confidence behind each classification;
- Never silently circumvention a 403 as an automatic fallback.

**If owner-authorized browser access is ever added:**
- It must have a distinct execution identity and authorization record;
- Its results must not be confused with unauthenticated observations.

**Boundaries:**
- Core sh4q remains scope-controlled discovery, observation, persistence, and
  reporting;
- Challenge-aware access is outside the current roadmap until its authorization
  and evidence requirements are designed properly;
- Sh4q stays trustworthy while leaving room for a more capable, carefully
  governed reconnaissance workflow later.

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
