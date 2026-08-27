# Inspecting Sh4q Results

Sh4q stores its durable results in `./sh4q-output/sh4q.db`. The database is the audit record; do not edit it manually during a scan.

Open it with:

```bash
sqlite3 ./sh4q-output/sh4q.db
```

Useful commands inside SQLite:

```sql
.headers on
.mode column

-- All discovered domains
SELECT value, attributes FROM nodes WHERE type = 'domain' ORDER BY value;

-- All IP addresses
SELECT value FROM nodes WHERE type = 'ip' ORDER BY value;

-- Hostnames that successfully resolved
SELECT d.value AS hostname, ip.value AS address
FROM relationships r
JOIN nodes d ON d.id = r.from_id
JOIN nodes ip ON ip.id = r.to_id
WHERE r.type = 'RESOLVES_TO'
ORDER BY hostname, address;

-- HTTP endpoints and recorded status
SELECT value, attributes FROM nodes WHERE type = 'url' ORDER BY value;

-- Evidence for one target, newest first
SELECT captured_at, plugin, kind, content
FROM evidence
WHERE target = 'example.com'
ORDER BY captured_at DESC
LIMIT 100;

-- Failed or unfinished durable events
SELECT status, attempts, error, updated_at
FROM event_log
WHERE status != 'COMPLETED'
ORDER BY updated_at DESC;
```

Exit with `.quit`.

## Planned Non-SQL Interface

Ordinary users should not need SQL. Planned interfaces include `sh4q results` with target/type/source filters, JSON and CSV export, and a self-contained HTML report showing assets, provenance, failures, and scan metrics.

The first non-SQL view is now available:

```bash
sh4q results --type domain --limit 100
sh4q results --type domain --target example.com
sh4q results --type ip
sh4q results --type ip --target example.com
sh4q results --type url
sh4q results --failures --target example.com
sh4q scans
```

Asset target filtering matches the exact root domain and its subdomains. IP filtering follows stored `RESOLVES_TO` relationships from matching domains. These are historical target views across the database, not exact per-scan views. First-class `scan_run` records are required before `--latest` and exact per-scan asset views can be implemented correctly.

The first scan-run view is now available:

```bash
sh4q scans --limit 20
sh4q results --latest --type domain
sh4q results --latest --target example.com
sh4q results --scan <scan-id> --type ip
sh4q export --latest --format json --output latest.json
sh4q export --latest --target example.com --format csv --output example.csv
sh4q export --scan <scan-id> --format json --output scan.json
```

It lists run IDs, targets, timestamps, and status. New scans attach evidence and accepted asset relationships to the run ID, enabling exact `results --scan <id>` and `results --latest` views. Scans created before this migration have no run ownership and remain accessible only through historical target filtering.

Exports require an exact scan selection through `--scan` or `--latest`. JSON includes scan metadata, structured attributes, asset values, and source plugins. CSV provides one asset per row for spreadsheets. Existing files are protected; use `--force` only when replacement is intentional. Pre-migration scans cannot be exported as exact runs because they have no scan ownership.

If a run has evidence but no scan-owned assets, Sh4q reports that it predates the asset-ownership migration instead of creating a misleading empty export. `--latest` selects only completed scans; unfinished runs remain visible through `sh4q scans`.
