# Changelog

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
