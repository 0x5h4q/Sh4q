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

## Remaining v1 Gates

1. **Terminal audit:** align scan overview, summary, results, events, failures,
   and export messages across wide, narrow, redirected, and non-TTY output.
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
5. **Release review:** acceptance scan complete. A clean native Tesla scan
   completed all core stages and its HTML report was reviewed against the
   terminal summary. Final release tagging remains.

## Adapter Policy

The v1 adapter set is intentionally small:

- Native DNS, HTTP, CT, and technology observation paths remain the baseline.
- Subfinder remains an opt-in passive discovery adapter. Amass remains opt-in
  and experimental; v1 acceptance does not depend on it producing results.
- ProjectDiscovery HTTPX remains opt-in endpoint enrichment with separately
  reported external-tool accounting.
- A passive URL-history adapter based on waybackurls (with gau as a later
  broader option) is a post-v1
  candidate, pending licensing, scope filtering, provenance, and offline tests.
- Nmap, Naabu, Nuclei, ffuf, and other active scanners are post-v1 candidates.
  They require a separate policy decision, stronger resource controls, and
  explicit authorization UX; adding them now would weaken the v1 focus.

## Post-v1 Capability Map

The following is the current planning boundary; “post-v1” does not imply a
guaranteed delivery date or automatic inclusion in v2:

- **Phase 3 / post-v1:** JavaScript endpoint and secret-pattern extraction,
  deeper passive intelligence, cloud enumeration, and screenshots.
- **Post-v1 candidate:** passive URL history through waybackurls, with gau as a
  comparable provider. The contract/parser slice is implemented, but live CLI
  wiring requires scope filtering, provenance, bounded output, licensing review,
  and an end-to-end offline pipeline test. The evidence/ownership pipeline and
  scheduler integration test are now complete; provider review and CLI release
  gating remain.
- **Post-v1 candidate:** virtual-host enumeration and directory/content
  discovery. These are active or potentially high-volume workflows and need a
  separate authorization and resource-control design.
- **Separate policy candidates:** Nmap, Naabu, Nuclei, ffuf, and other active
  scanners. They are not promised v2 features and must not be enabled by
  implication through a generic adapter interface.
- **Phase 4 / v2.0 direction:** dashboard, API, distributed workers,
  PostgreSQL/Redis/NATS, authentication, and RBAC.
- **Phase 5 / later direction:** historical tracking, scan diffs, graph
  visualization, AI summarization, and prioritization.

## Post-v1 Engineering Backlog

Prioritized work after the v1 review release:

1. **Passive URL history:** add a waybackurls-style adapter only after
   scope filtering, provenance, bounded output, licensing, and offline tests
   are defined.
2. **Scan-to-scan diffs:** identify new, removed, and changed assets and
   relationships without rewriting immutable evidence.
3. **Large-scan operations:** improve progress reporting, adaptive scheduling,
   timeout summaries, and partial-completion UX for unreliable providers.
4. **Documentation QA:** add automated checks for README links, version
   strings, release status, and stale roadmap claims.
5. **Export handling:** add deliberate redaction controls for query parameters,
   sensitive evidence, and internal-looking hostnames before sharing reports.
6. **Schema evolution:** introduce numbered SQLite migrations before adding
   features that change persisted records or ownership semantics.
7. **Controlled enrichment:** evaluate JavaScript extraction, vhost discovery,
   directory discovery, and active adapters separately with explicit policy,
   resource, and authorization designs.

Each item should retain the v1 invariants: Gate 1 and Gate 2 enforcement,
evidence-first handling, scan ownership, provenance, bounded execution, and
offline regression coverage. Breadth should be added only when it improves the
operator workflow without weakening those controls.

## v1 Definition Of Done

v1 is ready when a new user can install Sh4q, run an authorised scan, understand
what was contacted and why, distinguish discovery from verification, inspect a
terminal or HTML report, reproduce the offline tests, and see documented limits
without relying on undocumented assumptions.
