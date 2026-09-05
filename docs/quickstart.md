# Quick Start

This guide assumes Sh4q is installed and the target is yours or covered by explicit permission.

## What Sh4q Does

Sh4q builds an inventory of an authorised domain. It can find names, check DNS,
check HTTP responses, identify technologies, and preserve details for review.

## 1. Start with a Basic Scan

```bash
sh4q scan your-domain.example
```

Without a configuration file, Sh4q permits the target hostname and its
subdomains on HTTP/HTTPS ports. Only use domains you own or are explicitly
authorised to test.

Record the scan ID printed in the summary.

## 2. Review the Scan

```bash
sh4q show --latest --target your-domain.example
```

This shows what resolved, what answered over HTTP, what passive sources found,
what failed, and how long each stage took.

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

## 3. Optional Discovery Modes

If Subfinder is installed:

```bash
sh4q scan your-domain.example --sub
```

This can take several minutes. Sh4q checks each returned name before using it.
The normal flow is:

```text
dns -> http -> ct -> subfinder -> discovered-dns -> discovered-http
```

For archived URLs:

```bash
sh4q scan your-domain.example --url-history
```

These are historical clues, not proof that pages are live today.

For passive JavaScript and HTML references from collected HTTP responses:

```bash
sh4q scan your-domain.example --js
```

To additionally fetch and passively inspect a bounded set of same-scope script
bundles, opt in explicitly:

```bash
sh4q scan your-domain.example --js-bundles
```

Review the extracted references directly:

```bash
sh4q results --latest --type javascript
```

On larger scans, narrow the view to script files, endpoint references, or
secret-like pattern indicators:

```bash
sh4q results --latest --type javascript --js-kind script_url
sh4q results --latest --type javascript --js-kind endpoint_reference
sh4q results --latest --type javascript --js-kind secret_like_pattern
```

These are passive, unverified observations. Sh4q does not execute JavaScript,
validate credentials, or automatically request extracted URLs.

### Reading the words in the output

- **Found:** a source reported a name or URL.
- **Resolved:** DNS returned an address.
- **Responded:** an HTTP request received a response. A `403` still counts as
  a response; it does not mean access was granted.
- **Technology:** a clue in an already-collected response, not a guarantee of
  the software or version in use.
- **Historical URL:** an archived URL that may no longer exist.
- **Rejected:** Sh4q kept the observation for audit purposes but did not add it
  to the trusted results because it was outside the configured scope or unsafe.

Passive names are not automatically described as live. Sh4q first validates scope, attempts DNS resolution, then probes only successfully resolved names.

## 4. Inspect Exact Scan Results

### A realistic authorised scenario

For a fictional engagement, suppose a bank authorises `*.acme-bank.example`
but excludes an internal hostname and a third-party payment service. Put those
boundaries in YAML and run the scan with `--config`. If a discovery points to a
private address or an excluded redirect, Sh4q records the observation but does
not add it to the trusted results. This is the practical difference between a
name being found and an asset being accepted.

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
