# Sh4q v1 Baseline

This document defines the v1 implementation that should remain stable while
post-v1 development proceeds. It is the reference point for regression tests,
release notes, demonstrations, and the academic evaluation.

## Purpose

Sh4q v1 is a local control and evidence layer for authorised reconnaissance. It
coordinates discovery tools, checks destinations against policy, and produces a
reviewable inventory. It is not a vulnerability scanner, exploitation tool, or
replacement for broad specialist suites.

The v1 promise is explainability and control:

```text
discover -> validate scope -> preserve evidence -> report what happened
```

## User Workflow

1. The operator supplies a target and optional configuration.
2. Gate 1 validates the initial target.
3. The scheduler runs the selected stages with retries, timeouts, and progress
   events.
4. Gate 2 checks discovered hostnames, addresses, HTTP destinations, and
   redirects before trusted persistence.
5. SQLite records the scan, accepted assets, relationships, evidence, failures,
   technology signals, and source ownership.
6. The operator reviews terminal output or exports JSON, CSV, HTML, or a scan
   diff.

## Included Stages

### Native stages

- **DNS:** resolves the target and discovered names and rejects non-public
  addresses by default.
- **HTTP:** checks approved HTTP/HTTPS destinations, records status and
  redirects, and reauthorises each redirect hop.
- **CT:** collects certificate-transparency names from supported providers and
  labels provider degradation, timeouts, and rate limits.
- **Technology observation:** records conservative signals from already
  authorised HTTP responses; a signal is not treated as proof of deployment.

### Optional adapters

- **Subfinder:** passive subdomain discovery.
- **Amass passive:** passive discovery, explicitly experimental and capped by
  execution timeout.
- **Waybackurls:** passive historical URL discovery, opt-in, stdin-driven,
  scope-filtered, bounded to 2,000 retained URLs, with raw provider evidence
  retained when truncation occurs.
- **ProjectDiscovery HTTPX:** endpoint enrichment for scan-owned, reauthorised
  HTTP inputs. Its external process traffic is accounted for separately from
  Sh4q's native HTTP client.

## Safety and Integrity Controls

- Gate 1 rejects an unauthorised initial target.
- Gate 2 prevents out-of-scope or unsafe discoveries from becoming trusted
  assets.
- Loopback, private, link-local, multicast, reserved, and otherwise non-public
  addresses are denied by default.
- Redirects are checked hop by hop.
- Native HTTP connects to an approved address while preserving hostname identity
  for TLS and the `Host` header.
- External commands use executable allow-lists, argument arrays, bounded output,
  timeouts, reduced environments, and no shell interpolation.
- Raw observations and failures remain evidence even when the result is denied.
- Scan ownership distinguishes one run's observations from the deduplicated
  global asset graph.
- Event handlers are idempotent because delivery is durable and at least once.

These controls reduce accidental scope violations. They do not establish legal
authorisation, guarantee provider correctness, or contain every packet emitted
inside an external tool.

## Data Model

The v1 SQLite database stores:

- scan runs and lifecycle status;
- typed assets such as domains, IP addresses, URLs, and technologies;
- relationships such as resolution, service, historical observation, and
  technology association;
- raw evidence, source/plugin identity, command context, and timestamps;
- failures, retries, provider status, and request accounting;
- scan-owned observations used by `--scan` and `--latest` views.

The database is local runtime data and may contain sensitive target information;
it must not be committed or shared without review.

## Outputs

The CLI provides scan summaries, scan overviews, filtered results, failure
views, and technology details. Exports include:

- JSON for programmatic use;
- CSV for spreadsheets and simple pipelines;
- self-contained HTML with offline filters and evidence context;
- scan-to-scan diffs showing new, removed, and changed records.

The HTML report is a presentation of the stored scan record, not a second data
collection path. Export redaction changes only the exported file.

## Reliability Baseline

The v1 baseline includes deterministic offline checks, scheduler and adapter
integration checks, HTML/browser checks, SQLite concurrency checks, packaging
verification, and authorised acceptance scans. The full offline suite previously
passed 43/43 under Python 3.12. Live provider results remain variable and are
not release-quality correctness tests.

Amass remains experimental because passive execution can stall. Certificate
providers, DNS resolvers, and HTTP endpoints can time out, rate-limit, or return
incomplete data without indicating a Sh4q defect.

## Explicit Non-Goals

The following are outside v1:

- exploitation or vulnerability verification;
- broad active port scanning and content fuzzing;
- guaranteed-complete attack-surface inventory;
- distributed workers or multi-user access control;
- a dashboard or public API;
- PostgreSQL as a required deployment database;
- exact resumption inside an interrupted network operation;
- protection against a malicious local user who can modify the database or
  runtime environment.

## Freeze Rules

Post-v1 work must preserve these v1 invariants:

1. Scope checks happen before trusted persistence and before native contact.
2. Denied and failed observations remain reviewable evidence.
3. Scan ownership and immutable evidence are not rewritten by later scans.
4. External execution remains bounded and allow-listed.
5. New persisted concepts receive an explicit schema migration.
6. Every shared behavior change receives an offline regression check.

New features may extend the system, but they should not silently change the
meaning of existing statuses, relationships, exports, or safety decisions.

## Release Identity

The package currently declares version `0.1.0`. The repository has used alpha
tags during development; the final `v0.1.0` tag should be created only after
the baseline is reviewed, tests are rerun, documentation links are checked,
and the exact commit is recorded. Do not move an existing alpha tag or reuse a
release tag for a materially different implementation.

For academic work, record the final v1 commit, tag/archive, Python version,
dependency lock state, configuration, test output, database schema version,
and representative authorised scans. Later v2 changes must be evaluated as a
separate snapshot.
