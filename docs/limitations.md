# Known Limitations

This list describes the private-alpha boundary. It should be read before judging scan output.

## Discovery and Providers

- Certificate-transparency services can time out, return errors, or rate-limit requests.
- Subfinder output varies with provider availability, configuration, cache state, and network conditions.
- Passive names can be stale, wildcard-generated, or nonexistent.
- Discovered-host DNS resolution is bounded to the first 500 accepted Subfinder names per scan.
- Discovered HTTP probing is bounded to the first 200 successfully resolved names.
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
- The private-alpha package is source-based and currently requires Python and a local virtual environment; no standalone binary is provided.
- Technology detection uses a curated offline signature set over a bounded response sample. It is intentionally smaller than Wappalyzer and does not execute page JavaScript or make additional fingerprinting requests.
