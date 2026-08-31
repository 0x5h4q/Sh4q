# Quick Start

This guide assumes Sh4q is installed and the target is yours or covered by explicit permission.

## 1. Start with a Native Scan

```bash
sh4q scan your-domain.example
```

Without a configuration file, Sh4q derives a narrow scope from the target and permits that hostname and its subdomains on HTTP/HTTPS ports.

Record the scan ID printed in the summary.

## 2. Review the Scan

```bash
sh4q show --latest --target your-domain.example
```

This separates verified DNS/HTTP surface, stored records, failures, request metrics, and persisted stage performance.

List URLs that returned an HTTP response:

```bash
sh4q results --latest --target your-domain.example --type url
```

List technology observations and their supporting signals:

```bash
sh4q results --latest --target your-domain.example --type technology
```

Technology matching is performed locally against responses already admitted by Sh4q. It does not create a second fingerprinting request. Exact versions appear only when an inspected header, meta value, script path, stylesheet path, cookie, or HTML marker explicitly exposes one.

A `403` or `404` still means an HTTP server responded. It does not mean access was granted or the application is healthy.

## 3. Use Subfinder Only When Needed

If Subfinder is installed:

```bash
sh4q scan your-domain.example --sub
```

This can take several minutes. The stages are:

```text
dns -> http -> ct -> subfinder -> discovered-dns -> discovered-http
```

Passive names are not automatically described as live. Sh4q first validates scope, attempts DNS resolution, then probes only successfully resolved names.

## 4. Inspect Exact Scan Results

List recent scans:

```bash
sh4q scans
```

Inspect durable processing health:

```bash
sh4q events --target your-domain.example
```

The default event view groups records by target, source stage, discovery kind, and status. It is mainly useful for confirming that discoveries completed, identifying retries or dead letters, and auditing recovery after interruption. Use `--details` only when individual event IDs are needed.

Use an exact scan ID when comparing runs:

```bash
sh4q show --scan <scan-id>
sh4q results --scan <scan-id> --type domain --limit 200
sh4q results --scan <scan-id> --type url --limit 200
sh4q results --scan <scan-id> --type technology --limit 200
```

## 5. Export Results

All scan-owned assets:

```bash
sh4q export --scan <scan-id> --format json --output scan.json
```

DNS-verified domains and addresses:

```bash
sh4q export --scan <scan-id> --alive dns \
  --format csv --output dns-alive.csv
```

HTTP-responsive domains, endpoints, and status codes:

```bash
sh4q export --scan <scan-id> --alive http \
  --format csv --output http-alive.csv
```

Technology observations:

```bash
sh4q export --scan <scan-id> --type technology \
  --format csv --output technologies.csv
```

Combined HTTP inventory with statuses, resolved addresses, and technologies:

```bash
sh4q export --scan <scan-id> --type http-inventory \
  --format csv --output http-inventory.csv
```

Sh4q refuses to overwrite an existing export unless `--force` is supplied.

## 6. Stop a Scan Cleanly

Press `Ctrl+C` once. Sh4q should print:

```text
Scan interrupted by user.
Unfinished durable events will be recovered on the next scan.
```

The interrupted scan remains visible through `sh4q scans`. A later scan may recover unfinished durable events, but an interrupted external or network call restarts rather than resuming halfway through.
