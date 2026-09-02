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
explicitly labelled as HTTP status. Structural QA passes; remaining work is
browser-level verification on supported desktop and mobile runtimes.
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
5. **Release review:** audit every public claim against the threat model and
   limitations, then run a clean authorised-domain acceptance scan.

## Adapter Policy

The v1 adapter set is intentionally small:

- Native DNS, HTTP, CT, and technology observation paths remain the baseline.
- Subfinder and passive Amass remain opt-in passive discovery adapters.
- ProjectDiscovery HTTPX remains opt-in endpoint enrichment with separately
  reported external-tool accounting.
- A passive URL-history adapter such as gau or waybackurls is a post-v1
  candidate, pending licensing, scope filtering, provenance, and offline tests.
- Nmap, Naabu, Nuclei, ffuf, and other active scanners are post-v1 candidates.
  They require a separate policy decision, stronger resource controls, and
  explicit authorization UX; adding them now would weaken the v1 focus.

## v1 Definition Of Done

v1 is ready when a new user can install Sh4q, run an authorised scan, understand
what was contacted and why, distinguish discovery from verification, inspect a
terminal or HTML report, reproduce the offline tests, and see documented limits
without relying on undocumented assumptions.
