# Changelog

## 1.4.0 - 2026-10-06

Correctness release. Two scope-authorization fixes change what enters the
asset graph, and one changes what a scan records, so read the first two
sections before comparing results with a v1.3.0 run.

### Security and correctness

- Fixed a Gate 2 bypass in `dns_resolution`. The handler saved its domain
  node before any check and only ever validated the resolved address, on
  the reasoning that Gate 1 had already authorized the hostname. That
  holds only while the event belongs to the scan currently running. Event
  delivery is durable and recovery filters on neither target nor scan, so
  one database could hand a later scan an unfinished event from a scan of
  a different target -- and the domain, its address, and the relationship
  entered the new scan's graph unauthorized. No request was ever made out
  of scope: the request-time gate was never affected, and the defect was
  graph integrity. Every handler that persists a hostname now authorizes
  it under the scope handling the event.
- `scope.ports` now gates inventory as well as contact. Only directory
  discovery checked the port before persisting; six other handlers
  authorized the hostname and ignored it, so a URL on a port you never
  authorized became an asset. Live scans were shielded by plugin-side
  checks, which is the same reasoning that made the bypass above look
  safe. A refused URL stays in evidence and is reported as refused.
- The authorization perimeter refuses strings that cannot name a host.
  Subdomain inheritance is granted by a suffix match, and `.example.com`,
  `sub..example.com` and `*.example.com` all satisfied it: they were
  authorized, became domain nodes, and were handed on to be resolved. A
  malformed entry in `scope.targets` now matches nothing, so a typo
  cannot act as a looser rule than the name it was meant to be.

### Scanning

- Added `crt.name` as an opt-in certificate-transparency source, and made
  the source list configurable through `certificate_transparency.sources`.
  On one engagement crt.sh timed out on all three attempts while
  crt.name returned 1750 names against certspotter's 176. Narrowing the
  list is also the only disclosure control currently available.
- A provider that refuses terminally is no longer re-queried. A
  non-retryable error is now cached like a rate limit, so a stage retry
  driven by one provider stops re-asking another that already gave its
  final answer, and the refusal reports the reason the service gave.
- `enrichment.max_names_resolved` and `max_hosts_probed` make coverage
  configurable, and the stage deadlines derive from them. A flat 300s
  could not bound 1500 names -- at ten lookups in flight and a three
  second per-name timeout that needs 450s -- so a large bound was cut off
  by arithmetic before the scan started.
- `--resolve` and `--hosts-file` resolve and probe discovered or
  operator-supplied names. Selection among more candidates than the bound
  prefers operator-supplied names, then names more than one source
  corroborates, then spreads the remainder evenly: taking the
  alphabetically first N spent 62% of a 500-name budget on hostnames
  beginning with "c".

### Reporting

- Added a third-party disclosure ledger: `results --disclosures` reports
  which external services learned about the target, in two tiers.
  Observed means sh4q made the request, so service and subject are both
  known; declared means an external tool made requests sh4q never saw, so
  only what it documents contacting can be stated. Every scan also prints
  what it is about to disclose before it does.
- Every listing states how much of the matching set it shows, and a
  requested `--limit` is honoured rather than silently clamped. The
  technology view reported "100" where the real total was 194; `--names`
  reported 1000 of 1209; `events --details` showed 10 of 7179 and said
  nothing.
- A stage cut off at its deadline keeps its completed work and says it
  was cut off. `discovered-dns` had preserved partial results longer than
  any other stage and never reported the truncation: on a real scan it
  announced 1500 names, ran past its deadline, and 189 left no resolution
  and no error while the stage printed COMPLETE.
- `--redact` reports how many URL-bearing fields it rewrote, and reaches
  all of them. It previously covered only url asset values, leaving the
  technology and HTTP-inventory endpoint columns, the exported JavaScript
  observations, and the report's own embedded JSON unredacted. It also
  rebuilt query strings unconditionally, altering 8 of 238 real URLs
  while removing nothing.
- JavaScript observations say which references are inventory. The view
  reads evidence, so it legitimately lists references Gate 2 refused; it
  now marks them rather than showing them beside real assets.
- Added `results --names` and `--response-attributes`: hostname
  composition by resolution outcome and leftmost label, and the cookie
  flags and review headers each endpoint sent.
- A suggested follow-up command carries the scope selector the run used.
  Without it, following the advice after a `--config` run silently fell
  back to a target-only scope and, for a private-address lab, refused
  every address it had just resolved.

### Documentation

- Install instructions recommend `@main`, with tags described as
  snapshots. A tag three days old was already 34 merges behind, two of
  them scope fixes.
- `docs/limitations.md` gains sections on scope matching and on
  attribution and third-party disclosure, including the two gaps that
  remain: no custom `User-Agent`, and no proxy or egress control.

## 1.3.0 - 2026-09-28

Correctness and workflow release. Three of the fixes below change what a scan
reaches or records, so read those before comparing results with a v1.2.0 run.

### Security and correctness

- Fixed a Gate 2 bypass: `subdomain_found` persisted its parent domain before
  any authorization ran, and never authorized the parent at all. Plugin and
  adapter output is untrusted by design, so an out-of-scope parent could enter
  the asset graph. Every current plugin sets the parent to the Gate 1 target,
  so no existing scan changes behaviour; the hole is now closed.
- Virtual-host probes are counted against the shared request budget. They
  previously ran outside it, ignored `max_concurrent`, and never appeared in
  request metrics, so recorded traffic undercounted what a `--vhosts` scan
  actually sent. Budget exhaustion is now recorded as a denial rather than an
  error.
- Virtual-host probes reach the port they were authorized for. `endpoint_port`
  was used for the scope check but never in the request URL, so a stage
  configured for a non-default port authorized one service and contacted
  another.
- Added regression coverage for the authorization perimeter itself: both
  gates, all six reserved address classes over IPv4 and IPv6, IDNA and
  homoglyph normalization, and fail-closed handling of unparseable input.

### Scanning

- `scope.ports` now selects which origins are probed, not only which are
  permitted. A configuration naming a non-standard port previously produced a
  clean scan that reached nothing. Ports with an unambiguous scheme use it;
  any other port is probed over both. A default 80/443 scope is unchanged.
- Directory discovery compares candidates against a randomly generated path
  that cannot exist, so an ordinary 404 is recognised instead of being
  reported as a candidate finding. Results matching the server's not-found
  response stay in evidence without becoming assets.
- Added named scan templates: a versioned YAML file declaring a name, an
  optional configuration, and an explicit stage list. A template owns stage
  selection, so combining it with `--config`, `--profile`, or a stage flag is
  an error rather than a silent override. Paths inside a template resolve
  relative to the template.

### Removed

- Retired the Amass adapter. Amass stopped printing discovered names to
  standard output at v4, so the adapter read an empty stream and reported a
  successful stage with no discoveries. `--amass` now explains the retirement
  and points at `--sub`; it is removed in the next major version.
- Removed `sh4q/config/example_com.yaml`, which listed `0.0.0.0/0` alongside a
  domain and therefore authorized every address on the internet. Replaced by
  `config/example-scope.yaml`.

### Output

- Scan output now separates findings from noise. An observation worth review
  is emphasised, a dismissed result is dimmed, and a Gate 2 refusal has its
  own marker rather than sharing the error marker, since a refusal is the
  perimeter working. Internal classification values no longer appear in the
  terminal. Colour applies only to an interactive terminal and is disabled by
  `NO_COLOR`.
- Corrected `--profile full`, which described itself as enabling all adapters
  while deliberately excluding amass and katana.

### Testing and documentation

- The offline suite runs 77 tests, up from 43 at v1.0.0 and 59 at the start of
  this cycle. Every file in `tests/` now belongs to exactly one list, network
  tests are separated behind `--network`, and the runner warns about any test
  file no list claims.
- Added `RELEASING.md`, documenting versioning rules, the release checklist,
  hotfix and rollback handling, and the fact that releases are built and
  verified locally because remote CI is unavailable.
- Documented how observation labels are decided, how ports drive probing, and
  the limits of the virtual-host and directory stages. Architecture, threat
  model, and mental-model diagrams are now rendered flowcharts.

Verified locally on Python 3.14.4: 77/77 offline tests, documentation QA,
configuration schema checks, and an end-to-end scan against a local lab target
exercising the virtual-host, directory, JavaScript, and template paths. GitHub
Actions remains unavailable, so no automated release validation ran.

## 1.2.0 - 2026-09-11

Post-1.1 maintenance and controlled discovery release.

- Added restrictive SQLite indexes for large-scan result, evidence, event,
  relationship, and node queries.
- Added quiet and verbose scan output modes plus JSON Lines progress events.
- Added a consolidated operator reference and expanded installation guidance.
- Added bounded, explicitly opt-in directory discovery with candidate
  normalization, scope checks, request budgets, baseline comparison, durable
  evidence, scan ownership, and HTML reporting.
- Added offline regression coverage for directory discovery and its report
  presentation.

The release is published from the `v1.2.0` tag. Automated release validation
remains unavailable while GitHub Actions access is disabled.

## 1.1.1 - 2026-09-06

Patch release following `v1.1.0`. Scan behaviour is unchanged; the HTML
report is not.

- Corrected the package version and release metadata, which `v1.1.0` shipped
  inconsistently.
- Fixed dark-theme contrast in the HTML report.
- Improved report filtering and interaction.
- Replaced the banner assets.

An earlier version of this entry described the release as a metadata
correction alone. It also changed the HTML report.

## 1.1.0 - 2026-09-06

Backward-compatible workflow and reporting improvements.

- Added bounded passive JavaScript extraction and same-scope bundle inspection.
- Added JavaScript observations to CLI results, exports, and HTML reports.
- Added `--profile web` and `--profile full` scan presets.
- Fixed HTTP probes to honor configured timeouts and retry transient overall
  timeouts with bounded scheduler retries.
- Added discovered-host JavaScript extraction and improved bundle failure
  isolation.
- Improved HTML report filtering, sorting, pagination, copy actions,
  collapsible sections, and light/dark theme support.
- Updated documentation and README branding assets.

## 1.0.0 - 2026-09-03

First v1 review release. Sh4q provides policy-controlled, evidence-backed
reconnaissance orchestration for authorised domain discovery.

- Native DNS, HTTP, CT, discovered-host enrichment, and conservative technology
  observations.
- Scope authorization and discovery validation with redirect and reserved-
  address controls.
- Durable evidence, event recovery, scan ownership, retries, and structured
  JSON/CSV/HTML exports.
- Self-contained responsive HTML reports with offline filters and packaged
  branded banner assets.
- Controlled Subfinder and ProjectDiscovery HTTPX adapters; passive Amass is
  experimental and optional with a bounded process ceiling.
- 43/43 deterministic offline tests, repeated SQLite concurrency validation,
  Chromium desktop/mobile report checks, and fresh-wheel installation QA.

Known limitations and post-v1 work are documented in `docs/limitations.md` and
`docs/v1_roadmap.md`.

## 0.1.0-alpha.53 - 2026-09-03

- Bounded and clearly labelled passive Amass as an experimental best-effort
  adapter with a 20-second process ceiling.
- Updated the architecture review, academic evaluation addendum, README, and
  v1 roadmap to reflect the verified implementation and remaining release gate.
- Corrected stale roadmap phases and acceptance criteria in the architecture
  review document.

## 0.1.0-alpha.52 - 2026-09-03

- Added the transparent branded banner to HTML report package data so wheel
  installations embed the same hero as source checkouts.
- Verified HTML reports in Chromium at desktop and mobile viewports, including
  filter/reset interactions and overflow checks.
- Recorded 43/43 offline tests and repeated SQLite concurrency validation under
  Python 3.12.

## 0.1.0-alpha.8 - 2026-08-31

- Added `sh4q banner` for the full Unicode block-art identity on wide interactive terminals.
- Preserved the compact graph identity for narrow terminals and redirected output.

## 0.1.0-alpha.7 - 2026-08-31

- Replaced the repetitive default event listing with grouped operational status by target, source, discovery kind, status, count, and retries.
- Kept individual durable records available through `sh4q events --details`.
- Reformatted scan summaries as compact tables and clarified relationship counts as asset links.
- Added a restrained graph-style ASCII identity for interactive scan summaries.

## 0.1.0-alpha.6 - 2026-08-31

- Added a data-driven offline technology signature engine over already-authorised HTTP responses.
- Added structured meta, script, and stylesheet extraction within the existing 64 KiB response sample.
- Added curated signatures with explicit version capture for common CMS, frameworks, libraries, platforms, runtimes, and CDN/WAF signals.
- Added signature-engine provenance to technology exports without generating additional network requests.

## 0.1.0-alpha.5 - 2026-08-30

- Added a combined HTTP inventory export with endpoint status, resolved addresses, technologies, confidence, signals, and provenance.

## 0.1.0-alpha.4 - 2026-08-30

- Converted raw TLS errors into durable HTTP failure evidence.
- Isolated discovered-host probe failures so one hostname cannot terminate the entire HTTP enrichment stage.

## 0.1.0-alpha.3 - 2026-08-30

- Prevented discovered-host HTTP probes from timing out while waiting for Sh4q's own rate-limit queue.
- Network timeouts now apply to admitted discovered-host requests; the outer stage deadline still bounds total work.

## 0.1.0-alpha.2 - 2026-08-30

- Corrected `sh4q scans` asset counts to count distinct owned assets instead of relationship ownership rows.
- Added bounded table and narrow-terminal presentation for `results --failures`.

## 0.1.0-alpha.1 - 2026-08-30

Initial private-alpha release.

- Policy-controlled target and discovery scope checks.
- DNS, HTTP, certificate-transparency, and optional Subfinder discovery.
- DNS and HTTP enrichment for permitted discovered names.
- Durable evidence, event recovery, scan ownership, and SQLite schema safeguards.
- Scan overview, asset results, failure inspection, and aligned terminal tables.
- CSV and JSON export with DNS-alive, HTTP-alive, and technology views.
- Conservative technology observations from authorised HTTP responses.
- Deterministic offline test runner with 38 checks.

Known limitations are documented in `docs/limitations.md`.
