# Path To v1

Sh4q v1 is a defensible review release, not a promise to replace every mature
reconnaissance tool. The acceptance bar is reproducibility, policy clarity,
and useful reporting for authorised attack-surface discovery.

## Completed Foundation

- Scope authorization, hostname normalization, reserved-address policy, and
  hop-by-hop redirect checks.
- Durable evidence, event recovery, scan identity, scan-owned provenance, and
  JSON/CSV exports.
- Native DNS/HTTP/CT discovery with bounded discovered-DNS and discovered-HTTP
  enrichment.
- Controlled external adapters with argument allow-lists, timeouts, output
  limits, isolated environments, and tool-version evidence.
- Optional Subfinder, passive Amass, and ProjectDiscovery HTTPX integrations.
- Conservative technology observations with confidence and raw signals.
- Threat model, limitations, offline fixtures, CI configuration, and narrow
  terminal coverage.

The contributor backlog was reconciled against this roadmap on 2026-09-09.
Items already implemented are tracked as completed here; proposed work is
sequenced below by safety and user impact rather than copied as a second
roadmap.

## Remaining v1 Gates

1. **Terminal audit:** mostly complete. One final pass remains for newly added
   active stages and non-TTY/JSON output consistency.
2. **HTML reporting:** complete. Chromium verification passed at 1440x1000 and
   390x844: the hero rendered, filters loaded, no page-level horizontal overflow
   occurred, and filter/reset interactions produced the expected counts. The
   self-contained report is generated from scan-owned assets,
   relationships, evidence references, failures, stages, and request metrics.
   It must provide offline client-side filters for status codes, host/target,
   asset type, technology/category, source, and text search, with visible
   filtered-versus-total counts.
   The report now includes the asset table/filter slice, failure details, stage
   timings, request metrics, and an evidence index. Responsive visual polish is
   implemented; technology rows are endpoint-aware and the status control is
   explicitly labelled as HTTP status. Structural QA and Chromium desktop/mobile
   verification pass.
The banner is centered as the primary report hero, with scan identity below;
long asset values remain horizontally readable instead of wrapping per
character.
The hero now uses the supplied banner at a larger centered size, and
non-applicable asset fields render as `-` instead of ambiguous blank cells.
   Reports also embed the project banner as a self-contained data URI with
   responsive sizing and an accessible text fallback. The banner is also
   included in built wheels as package data.
   Narrow-terminal coverage now includes scan summaries and persisted overview
   fields as well as results, events, and failures.
3. **Reliability evaluation:** complete. The full offline runner passed `43/43`
   on Python 3.12, and five consecutive SQLite concurrency runs passed. Python
   3.14 remains experimental until it receives equivalent runtime coverage.
4. **Packaging and operations:** complete. A wheel was built and installed in
   a fresh Python 3.12 environment; `sh4q --help` completed successfully.
   Configuration, database handling, and sensitive-output guidance remain
   documented.
5. **Release review:** acceptance scans are complete for native, Katana, vhost,
   JavaScript, and reporting paths. Final tagging remains after the hardening
   and provider-fix work below.

## Adapter Policy

The v1 adapter set is intentionally small:

- Native DNS, HTTP, CT, and technology observation paths remain the baseline.
- Subfinder remains an opt-in passive discovery adapter. Amass remains opt-in
  and experimental; v1 acceptance does not depend on it producing results.
- ProjectDiscovery HTTPX remains opt-in endpoint enrichment with separately
  reported external-tool accounting.
- The passive URL-history adapter based on waybackurls is implemented with
  scope filtering, provenance, bounded output, and offline tests. Its provider
  invocation fix must be released before calling the stage production-ready;
  gau remains a later provider option.
- Nmap, Naabu, Nuclei, ffuf, and other active scanners are post-v1 candidates.
  They require a separate policy decision, stronger resource controls, and
  explicit authorization UX; adding them now would weaken the v1 focus.

## Post-v1 Capability Map

The following is the current planning boundary; “post-v1” does not imply a
guaranteed delivery date or automatic inclusion in v2:

- **Phase 3 / post-v1:** JavaScript endpoint and secret-pattern extraction,
  deeper passive intelligence, cloud enumeration, and screenshots.
- **Implemented controlled enrichment:** JavaScript extraction, bounded Katana,
  and bounded virtual-host discovery. Katana and vhost probing remain explicit
  opt-ins because they are active and potentially high-volume. Directory/content
  discovery has a design specification but no implementation yet.
- **Separate policy candidates:** Nmap, Naabu, Nuclei, ffuf, and other active
  scanners. They are not promised v2 features and must not be enabled by
  implication through a generic adapter interface.
- **Phase 4 / v2.0 direction:** dashboard, API, distributed workers,
  PostgreSQL/Redis/NATS, authentication, and RBAC.
- **Phase 5 / later direction:** historical tracking, scan diffs, graph
  visualization, AI summarization, and prioritization.

## Prioritized Engineering Backlog

Prioritized work after the v1 review release:

1. **Safety hardening:** rename the localhost-only sample configuration, warn
   when private addresses are explicitly enabled, enforce restrictive SQLite
   and output permissions, and make corrupted JSON/evidence records degrade
   with actionable diagnostics.
2. **Reproducible supply chain:** add dependency upper bounds, a release and
   development lock strategy, `pip-audit`, automated dependency updates, and
   pinned CI action references.
3. **URL-history release gate:** merge and test the Waybackurls argument-form
   fix, retain provider/raw-output evidence, and document provider limitations.
4. **Large-scan performance:** measure and add remaining SQLite indexes, batch
   writes where event ordering permits, and optimize export queries based on
   benchmarks. Do not introduce connection pooling without evidence that it
   improves scan throughput.
5. **Operator UX:** add configuration and CLI references, quiet/verbose modes,
   machine-readable progress events, consistent status formatting, and HTML
   report interpretation guidance.
6. **Controlled directory discovery:** implement the approved design only after
   offline path normalization, traversal rejection, baseline comparison,
   redirect, budget, persistence, and report tests exist.
7. **Distribution:** publish versioned wheels through PyPI or `pipx`, verify
   clean-environment installs, and keep release artifacts reproducible.
8. **Workflow foundations:** add versioned scope-file support, safe scan
   templates that disclose active stages, scheduled scans, proxy support, and
   inventory exports with first/last-seen metadata.
9. **Platform v2:** design the API, dashboard, worker queue, PostgreSQL-backed
   deployment, authentication/RBAC, and webhook integrations as a separate
   product milestone.

Current status: numbered SQLite migrations, scan diffs, export redaction, HTML
reporting, URL history, Katana, and vhost discovery are implemented with
offline coverage. The remaining release blockers are hardening,
reproducible dependency/release controls, and the URL-history provider
invocation fix.

Each item should retain the v1 invariants: Gate 1 and Gate 2 enforcement,
evidence-first handling, scan ownership, provenance, bounded execution, and
offline regression coverage. Breadth should be added only when it improves the
operator workflow without weakening those controls.

## v1 Definition Of Done

v1 is ready when a new user can install Sh4q, run an authorised scan, understand
what was contacted and why, distinguish discovery from verification, inspect a
terminal or HTML report, reproduce the offline tests, and see documented limits
without relying on undocumented assumptions.
