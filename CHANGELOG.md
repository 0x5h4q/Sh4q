# Changelog

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
