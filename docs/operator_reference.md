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

Certificate transparency runs by default and often returns the largest set of
names a scan finds, but those names are only names. Resolving them and probing
the ones that answer is a large traffic increase, so it is opt-in:

```bash
sh4q scan example.com --resolve
```

A list you already hold -- from a prior scan, a client inventory, or a
certificate dump -- can be checked the same way:

```bash
sh4q scan example.com --hosts-file candidates.txt
```

The file takes one hostname per line. URLs, `host:port` pairs, mixed case,
trailing dots, and `#` comments are all accepted and normalised; at most 500
names are allowed and an oversized file is refused rather than truncated.
Every name is authorised before it is contacted, so a list may safely contain
out-of-scope entries -- they are refused at Gate 2 and recorded. Supplying a
list enables resolution on its own; `--resolve` is not also required.

`--resolve` takes the subdomain names found during the scan, from certificate
transparency or Subfinder, resolves up to 500 of them, and probes up to 200
that answer. `--sub` implies it. Both stages draw on the same shared request
budget, so a large name list may exhaust it; the refusals are recorded.

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
| `stages` | yes | Any of `sub`, `resolve`, `httpx`, `url-history`, `js`, `js-bundles`, `katana`, `vhosts`, `directories`. No duplicates, no unknown names. |
| `config` | no | A configuration file, resolved relative to the template. Omit it to derive a narrow scope from the target on the command line. |
| `hosts_file` | no | A list of hostnames to resolve and probe alongside anything discovered. |
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

`scope.ports` does two things: it authorizes destinations, and it decides which
origins the HTTP stage probes. Every authorized port is probed. A port with an
unambiguous scheme uses it -- 80 and 8080 over HTTP, 443 and 8443 over HTTPS --
and any other port is probed over both, since guessing wrong would skip a
service silently. An empty port list authorizes every port, in which case the
well-known pair is probed rather than an unbounded sweep.

Virtual-host and directory discovery sweep a single origin rather than every
authorized port, so a candidate list is not multiplied by the port count. They
prefer HTTPS when it is authorized.

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

### Name composition

Certificate transparency returns every name a certificate was issued for, and
hosting panels request certificates for service subdomains on every hosted
domain. A large share of a CT result can therefore be names that were never
deployed.

```bash
sh4q results --latest --target example.com --names
```

```text
  Hostnames                  908
    resolved                 172
    did not resolve          329
    not checked              407   (run with --resolve)

  Service-prefix names       524 (58% of the total)
    of those, resolved       0
```

A prefix is a hint, not a verdict -- an organisation may genuinely run
`mail.example.com`, and a service-prefix name that resolves is counted as
resolved rather than dismissed. The figure that settles it is how many of them
answered, which requires `--resolve` or `--hosts-file`; names nothing tried are
reported as not checked rather than as failures.

### Response attributes

Every HTTP probe records the cookie attributes and review headers the server
sent. No extra request is made; these come from responses the scan already
fetched.

```bash
sh4q results --latest --target example.com --response-attributes
```

```text
  https://example.com/
    cookie  PHPSESSID    no Secure, no HttpOnly, no SameSite
    headers not sent: content-security-policy, strict-transport-security, x-frame-options
```

Cookie **values are never recorded** -- only the name and its attributes --
because a value is frequently a live session token and evidence is written to
disk and included in exports.

Sh4q does not grade these. A missing `Secure` flag on a host that redirects to
HTTPS and sets no cookie over plaintext is a different matter from the same
flag missing on a host that serves both; a missing `Content-Security-Policy`
on a static page is not the same as one on an application. The record is
factual and the judgement is the reader's.

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
Observation labels are explained under [Reading Observations](#reading-observations);
neither label is a security finding. Redaction removes
URL query values before sharing a report. The SQLite database and raw evidence
may contain sensitive target data; review them before distribution.

## Reading Observations

Virtual-host and directory discovery do not report what exists. They report
how a server's response to a probe **differed from a baseline**, and leave the
judgement to the operator. Both stages label every result, and the labels mean
specific things.

### Virtual hosts

A virtual-host probe sends a different `Host:` header to the *same* address.
The baseline is the response the server gives for the scan target's own name.
Each candidate is then compared against it.

| Label | Terminal | Meaning |
| --- | --- | --- |
| `default_vhost_match` | `[-] vhost ... same as the default host` | The server returned the same response as the baseline. It is not configured for this name and fell through to its default site. Not interesting. |
| `candidate_observation` | `[!] VHOST ... responds differently to this name` | The server answered this name differently, which is consistent with a separate virtual host being configured. Worth a look. |

`candidate_observation` is not proof. A different response can also come from
an error page, a redirect, a load balancer, or content that varies per request.
Sh4q reports the difference it measured and stops there.

### Directory paths

A directory probe requests a path and compares the response to two baselines:
the site root, and a **randomly generated path that cannot exist**, which
reveals what this particular server's "not found" looks like.

| Label | Terminal | Meaning |
| --- | --- | --- |
| `not_found_match` | `[-] path ... matches this server's not-found response` | The response matched the not-found baseline, repeated the root page (a soft 404), or carried the same error status. The path is absent. |
| `candidate_observation` | `[!] PATH ... distinct response` | The response differed from both baselines. Something is there. |

The random-path baseline matters: comparing only against the site root would
label every ordinary 404 as a candidate, because a 404 page never looks like a
homepage.

A `not_found_match` stays in the evidence record — it is part of what was
probed — but does not become a scan asset. That is why the evidence count and
the asset count differ.

### Output markers

| Marker | Meaning |
| --- | --- |
| `[!]` | An observation worth review |
| `[+]` | An authorised asset was stored |
| `[x]` | Gate 2 refused a destination. Expected policy behaviour, not a failure |
| `[-]` | A negative result, or an error |
| `[~]` | Progress |

Colour is used only when output is an interactive terminal. Piped or
redirected output is plain text, and setting `NO_COLOR` disables colour
entirely.

## Optional Dependencies

```bash
sh4q doctor
```

This reports whether optional external tools are available. A missing optional
tool does not affect the native scan, but requesting that stage will stop the
scan before execution.
