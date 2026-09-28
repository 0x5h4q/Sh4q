# Operator Reference

This reference describes the commands and options used to run and inspect an
authorised Sh4q scan. Sh4q is discovery-only: use it only for targets you own
or are explicitly permitted to assess.

## Scan Modes

```bash
sh4q scan example.com
```

The default scan runs native DNS, HTTP, and certificate-transparency discovery.

Progress output is detailed by default. Use `-q` for scripts or scheduled jobs
when only the final scan summary is needed; `-v` explicitly selects the
detailed stream.

```bash
sh4q scan example.com -q
sh4q scan example.com -v
```

For automation, emit one JSON object per lifecycle update:

```bash
sh4q scan example.com --progress jsonl
```

JSONL progress includes Gate 1, stage attempts, retries, timeouts, errors,
stage completion, and the final scan summary. Discovery records and evidence
remain available through the database and normal result commands.

Directory/content discovery is not enabled by any profile. It is available as
a separately bounded, operator-supplied wordlist stage and requires explicit
opt-in with `--directories --directories-file`.

Profiles enable tested passive bundles:

```bash
sh4q scan example.com --profile web
sh4q scan example.com --profile full
```

`web` enables JavaScript extraction and bounded JavaScript bundle inspection.
`full` additionally enables Subfinder, HTTPX enrichment, and URL history.

The following stages remain explicit opt-ins because they can be high-volume or
active:

```bash
sh4q scan example.com --katana
sh4q scan example.com -vh --vhosts-file candidates.txt
```

Virtual-host and directory discovery both probe at most one request per second,
are capped at 500 and 200 candidates respectively, and draw on the same
`rate_limit.budget` as every other stage. Exhausting that budget stops further
probes and records the refusal rather than failing the scan.

Virtual-host discovery requires either `--vhosts-file` or
`--vhosts-from-scan SCAN_ID`. A prior scan can provide bounded domain
candidates:

```bash
sh4q scan example.com -vh --vhosts-from-scan SCAN_ID
```

## Scan Templates

A template is a named, reviewable recipe: it records the stages a scan runs, so
a long command does not have to be remembered, retyped, or reconstructed from
shell history before a repeat run.

```bash
sh4q scan example.com --template config/example-template.yaml
```

Sh4q prints the template name and its stage list before the scan starts.

```yaml
schema_version: 1
name: passive-web-inventory
stages:
  - sub
  - httpx
  - url-history
  - js
  - js-bundles
```

Fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `schema_version` | yes | Must be `1`. Unsupported versions fail before any network activity. |
| `name` | yes | Shown before the scan runs. |
| `stages` | yes | Any of `sub`, `httpx`, `url-history`, `js`, `js-bundles`, `katana`, `vhosts`, `directories`. No duplicates, no unknown names. |
| `config` | no | A configuration file, resolved relative to the template. Omit it to derive a narrow scope from the target on the command line. |
| `vhosts_file` | no | Candidate file for the `vhosts` stage. |
| `directories_file` | no | Candidate file for the `directories` stage. Required whenever `directories` is selected. |

A template declares stages and configuration, so it cannot be combined with
`--config`, `--profile`, or any stage flag. Supplying one is an error rather
than a silent override, and the conflicting option is named:

```text
sh4q: error: --template cannot be combined with --sub; the template already
declares stages and configuration
```

A template selects existing bounded stages. It does not bypass Gate 1, Gate 2,
request budgets, evidence retention, or provenance, and it cannot enable an
active stage implicitly: `katana`, `vhosts`, and `directories` are only ever
run when the template lists them by name.

## Configuration

Use `--config path.yaml` to define scope, ports, rate limits, timeouts, output,
and adapter bounds. Without a config file, the target and its subdomains are
allowed on ports 80 and 443.

```yaml
schema_version: 1

scope:
  targets: ["example.com"]
  excluded: []
  ports: [80, 443]
  allow_private_addresses: false

rate_limit:
  max_concurrent: 3
  requests_per_second: 2.0
  budget: 1000

timeout:
  dns_seconds: 5.0
  http_seconds: 10.0

output:
  directory: "./sh4q-output"
  format: "json"

adapters:
  httpx:
    max_endpoints: 200
    timeout_seconds: 120.0
```

Private or reserved address access is denied by default. Enabling
`allow_private_addresses` is an explicit policy decision and should be limited
to controlled test environments.

`schema_version: 1` identifies the configuration contract. New files should
declare it explicitly. Existing unversioned files are treated as legacy version
1 files, while unsupported or malformed versions are rejected before any scan
or network activity starts.

## Inspecting Results

List recorded scans and inspect one overview:

```bash
sh4q scans
sh4q show --latest
sh4q show --scan SCAN_ID
```

List assets by type or source:

```bash
sh4q results --latest --type domain
sh4q results --latest --type url --source vhost-discovery
sh4q results --latest --type technology --details
sh4q results --latest --type javascript --js-kind endpoint_reference
```

Use `--target`, `--limit`, `--category`, `--status`, and
`--source-endpoint` to narrow output. Use `--failures` to inspect recorded
provider, DNS, HTTP, and adapter failures.

Durable event state is available for recovery and troubleshooting:

```bash
sh4q events --status FAILED --details
sh4q events --target example.com
```

## Export and Comparison

```bash
sh4q export --latest --format json --output scan.json
sh4q export --latest --format csv --output assets.csv --alive http
sh4q export --latest --format html --output report.html --redact
sh4q diff --before BEFORE_ID --after AFTER_ID --format text
```

The HTML report is self-contained and can be opened offline. The asset table
is the verified scan-owned surface; the JavaScript, vhost, and directory
sections contain bounded observations that still require operator review.
`not_found_match` means a directory response matched the baseline fingerprint;
`candidate_observation` means it differed from that baseline. Neither label is
a security finding. Redaction removes
URL query values before sharing a report. The SQLite database and raw evidence
may contain sensitive target data; review them before distribution.

## Optional Dependencies

```bash
sh4q doctor
```

This reports whether optional external tools are available. A missing optional
tool does not affect the native scan, but requesting that stage will stop the
scan before execution.
