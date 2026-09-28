# Known Limitations

This list describes the v1.3.0 boundary. It should be read before judging scan output.

## Discovery and Providers

- Certificate-transparency services can time out, return errors, or rate-limit requests.
- Subfinder output varies with provider availability, configuration, cache state, and network conditions.
- Passive names can be stale, wildcard-generated, or nonexistent.
- Discovered-host DNS resolution is bounded to the first 500 accepted Subfinder names per scan.
- Discovered HTTP probing is bounded to the first 200 successfully resolved names.
- A discovered-HTTP stage timeout does not retry the entire batch; completed
  per-host results are retained and unfinished probes are recorded as absent.
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

## Metrics and Reporting

- Native request metrics cover Sh4q's HTTP and CT traffic, not opaque provider traffic inside Subfinder or `httpx`.
- External `httpx` accounting reports admitted endpoints, reported responses, unreported endpoints, and tool processes separately from native requests.
- Stage metrics exist only for scans created after stage persistence was introduced.
- Migration-era scans may contain evidence without exact asset ownership and cannot be safely backfilled.
- Global assets are deduplicated, while evidence remains observation-oriented; counts therefore describe different things.
- Source ownership counts are not the same as raw provider result counts.

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
