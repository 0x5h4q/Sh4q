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
sh4q results --type ip
sh4q results --type url
sh4q results --failures --target example.com
```

Asset rows are currently global to the database because nodes do not yet carry a scan identifier. Failure evidence can be filtered by target. First-class `scan_run` records are required before `--latest` and exact per-scan asset views can be implemented correctly.
