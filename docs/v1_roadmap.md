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
2. **HTML reporting:** generate a self-contained report from scan-owned assets,
   relationships, evidence references, failures, stages, and request metrics.
3. **Reliability evaluation:** fix the full offline-runner/SQLite initialization
   hang, repeat concurrency and recovery checks, and publish measured results.
4. **Packaging and operations:** verify clean installation, configuration
   examples, database handling, sensitive-output guidance, and upgrade notes.
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

