# Known Limitations

This list describes the v1.3.0 boundary. It should be read before judging scan output.

## Discovery and Providers

- Certificate-transparency services can time out, return errors, or rate-limit requests.
- Subfinder output varies with provider availability, configuration, cache state, and network conditions.
- Passive names can be stale, wildcard-generated, or nonexistent.
- Discovered-host DNS resolution and HTTP probing are bounded by
  `enrichment.max_names_resolved` (default 500) and `enrichment.max_hosts_probed`
  (default 200). Both are configurable; see
  [operator_reference.md](operator_reference.md#coverage) before assuming the
  request budget is what limited a scan.
- Names are drawn from certificate transparency and Subfinder, plus any list
  supplied with `--hosts-file`.
- When more names are found than the bound allows, the selection is **not** the
  first N. Operator-supplied names come first, then names more than one source
  agrees on, then an even spread across the sorted remainder. Taking the
  alphabetically first N spent 62% of a 500-name budget on hostnames beginning
  with `c` and never reached anything after `m`. The selection is deterministic,
  but it is a sample: raise the bound rather than infer absence from it.
- A stage cut off at its deadline keeps what it completed rather than
  discarding it. `discovered-dns`, `discovered-http`, `vhost-discovery`,
  `directory-discovery`, `http`, `ct` and `javascript-bundles` all do this;
  `discovered-http` additionally reports hosts never contacted and directory
  discovery candidates never probed. A partial stage is never presented as a
  whole one, and a cancelled stage that preserved nothing is reported as
  incomplete rather than as an empty success.
- Two stages do not preserve partial results, deliberately.
  `javascript-extraction` has a single awaitable step, so either it completes
  or there is nothing to keep. `httpx-fingerprint` is one external process
  bounded by its own shorter timeout, which is already reported as an adapter
  execution failure.
- Transport exceptions with empty messages are reported with their exception
  class and phase so provider or TLS failures remain diagnosable.
- A scan is not proof that every asset was found.

## DNS and HTTP

- DNS results reflect the resolver and network conditions at scan time.
- NXDOMAIN, timeout, SERVFAIL, and no-answer conditions are observations, not permanent facts.
- HTTP `403`, `404`, and `500` responses still prove that an endpoint responded.
- A timeout does not prove that a host is permanently down.
- Redirects outside configured scope are blocked, which may prevent a final application page from being observed.
- Interrupted network or adapter calls restart on a later scan rather than resuming mid-call.

## Technology Observations

- Native fingerprinting is conservative and incomplete.
- Headers, cookies, and HTML markers can be absent, hidden, altered, or misleading.
- CDN or WAF technology may be visible while the origin stack remains hidden.
- Version values are retained only when explicitly exposed.
- Technology confidence is evidence quality, not certainty.
- Optional ProjectDiscovery `httpx` enrichment is endpoint-filtered and bounded, but its internal DNS and HTTP requests do not pass through Sh4q's native pinned-IP transport or request limiter.

## Virtual-Host and Directory Discovery

- Neither stage verifies anything. Each compares a response against a baseline
  and reports the difference; `candidate_observation` is a measured difference,
  not a confirmed virtual host or file.
- A differing response can come from an error page, a redirect, a load
  balancer, or content that varies between requests.
- A server that answers every name identically yields no candidates even when
  virtual hosts exist. A server that answers every path with a distinct page
  yields candidates for all of them.
- Candidate lists are operator-supplied and bounded: at most 500 virtual-host
  candidates and 200 directory paths, one request per second, drawn from the
  same shared request budget as every other stage. Exhausting that budget stops
  further probes and records the refusal.
- Both stages sweep a single origin, preferring HTTPS when authorized, rather
  than every authorized port. A service on a second port is not swept.
- Directory candidates are relative paths. Absolute URLs, traversal, query
  strings, fragments, credentials, and control characters are rejected before
  any request.
- A `not_found_match` is kept as evidence but is not an asset, so the evidence
  and asset counts for these stages differ by design.

## Ports

- `scope.ports` both authorizes destinations and selects which origins the HTTP
  stage probes. A port that is not authorized is never probed.
- Ports with an unambiguous scheme are probed over it; any other port is probed
  over both HTTP and HTTPS, which costs two requests rather than one.
- An empty port list authorizes every port. Sh4q does not sweep every port in
  that case: it probes 80 and 443 only. A non-standard service reachable under
  such a configuration will not be found unless its port is listed.
- `scope.ports` gates **inventory as well as contact**. A URL on an unauthorized
  port stays in evidence, where the record of what was observed belongs, but it
  does not become an asset. This matters most for passive sources: a historical
  URL from `waybackurls` on port 8443 is recorded and reported as refused, not
  added to the graph. The asset graph is the authorized subset, ports included.
  Widen `scope.ports` if you want those origins inventoried.

## Scope Matching

- A target is authorised by exact match, by subdomain inheritance
  (`sub.example.com` is in scope when `example.com` is listed), or by CIDR
  membership. The `excluded` list always wins.
- Names are normalised before every comparison: NFKC, trailing dot removed,
  IDNA encoding and case folding for hostnames, canonical form for addresses.
  Homoglyphs do not fold onto the names they imitate and are refused.
- A string that cannot name a host is refused rather than inherited. An empty
  label (`.example.com`, `sub..example.com`), a label over 63 characters, a
  wildcard (`*.example.com`) or an embedded authority delimiter is not a
  hostname, and the subdomain rule no longer accepts one. Certificate
  transparency strips the `*.` prefix of a wildcard certificate name before it
  reaches the engine, so no discovery is lost to this.
- A malformed entry in `scope.targets` matches nothing. A typo cannot act as a
  looser rule than the hostname it was meant to be.
- Authorisation of a hostname is separate from the safety of the address it
  resolves to; see `allow_private_addresses`.

## Attribution and Third-Party Disclosure

- Sh4q sends no custom `User-Agent`. Requests carry the HTTP client's default,
  so authorised traffic is not identifiable as authorised. A defender seeing it
  has no way to attribute it to you, and bug-bounty programmes that require an
  identifying header are not satisfied by any current option.
- A scan discloses the target to third parties, and nothing records which ones.
  Certificate transparency contacts `crt.sh` and `api.certspotter.com` directly
  on every default scan. `--sub` and `--url-history` pass the target to the
  `subfinder` and `waybackurls` subprocesses, which query their own providers --
  Subfinder's configured sources and the Internet Archive respectively -- so
  what they disclose, and to whom, is outside Sh4q's view and outside its
  request limiter. DNS queries go to the system resolver, one per name, which
  for most operators means their network's or ISP's resolver.
- Neither of the above is a policy position; both are unimplemented. If an
  engagement restricts what may be disclosed to third parties, review which
  stages you enable before running, not afterwards.
- There is no proxy or egress control, so requests originate from the host
  running the scan.

## Metrics and Reporting

- Native request metrics cover Sh4q's HTTP and CT traffic, not opaque provider traffic inside Subfinder or `httpx`.
- External `httpx` accounting reports admitted endpoints, reported responses, unreported endpoints, and tool processes separately from native requests.
- Stage metrics exist only for scans created after stage persistence was introduced.
- Migration-era scans may contain evidence without exact asset ownership and cannot be safely backfilled.
- Global assets are deduplicated, while evidence remains observation-oriented; counts therefore describe different things.
- Source ownership counts are not the same as raw provider result counts.
- Every listing states how much of the matching set it shows (`Showing 100 of
  194 ...`). A figure without a denominator is a defect, not a total. `--limit`
  is honoured as given; it is a display bound, not a query cap.
- The `events` summary groups events, so its `--limit` caps groups rather than
  events. The count inside each group is complete; the line beneath the table
  says how many events the shown groups actually account for.
- `--redact` reports how many URL-bearing fields it rewrote, because an export
  whose URLs carry no secret-keyed query parameter is byte-identical to an
  unredacted one and would otherwise be indistinguishable from redaction
  failing.

## Storage and Deployment

- SQLite is intended for a local, single-user research prototype.
- Sh4q is not a distributed service and has no multi-user access control.
- Structural database migrations are only beginning; schema version safeguards exist, but a complete migration framework does not.
- Scan output can be sensitive and is not encrypted by Sh4q.

## Product Scope

- Subfinder and ProjectDiscovery `httpx` have opt-in live external-tool adapters.
- Sh4q does not perform vulnerability exploitation.
- It does not currently crawl applications broadly or perform general port scanning.
- It is not a direct replacement for reconFTW, Amass, Nmap, or a commercial attack-surface management platform.
- The package is distributed as a Python wheel and source archive. A standalone
  native binary is not provided.
- Technology detection uses a curated offline signature set over a bounded response sample. It is intentionally smaller than Wappalyzer and does not execute page JavaScript or make additional fingerprinting requests.
- External adapter tools can be unavailable, misinstalled, or provider-blocked. Sh4q now fails fast when an adapter's bounded version probe hangs, but a working tool installation and provider configuration remain the operator's responsibility.
- The Amass adapter was retired after v1.2.0. Amass stopped printing
  discovered names to standard output at v4, so the adapter observed nothing
  and reported an empty stage. Use `--sub` instead.
- Any external tool that stalls in provider or local-database work may yield no
  names. Sh4q records the timeout and continues with the remaining stages.

## Review Status

The limitations review applies to the published `v1.3.0` release. The adapter
scheduler and provenance path is covered offline, but this does not turn
third-party tool output into a completeness or liveness guarantee.
