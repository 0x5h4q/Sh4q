# Passive URL-History Policy

This document defines the boundary for integrating a passive URL-history
provider such as `waybackurls` or `gau` into Sh4q. It is a design prerequisite,
not an indication that a provider is enabled in the current CLI.

## Purpose

URL history can reveal older paths, query shapes, and hostnames that are useful
for review. These are historical observations only. They do not demonstrate
that a URL is reachable now, safe to request, or in scope.

## Provider boundary

The initial integration target is `waybackurls` because it has one clearly
defined archive source and a minimal command interface. `gau` may be added
later as an explicitly broader provider with provider-level provenance.

- The operator must install and configure the external provider separately.
- Sh4q must invoke a fixed, passive command shape with no crawl, probe, or
  arbitrary output-path arguments.
- Provider output is untrusted input and is parsed line-by-line with bounded
  size and deduplication.
- Provider terms, API limits, and any applicable licensing obligations remain
  the operator's responsibility and must be reviewed before release.

## Scope and storage

- Gate 1 authorizes the requested root target before the adapter runs.
- Gate 2 validates every returned hostname before it becomes a trusted asset.
- Raw adapter output and execution metadata remain durable evidence.
- Accepted URLs are linked with `HISTORICAL_URL`; they must never create a
  `SERVES` relationship or increase live HTTP counts.
- Out-of-scope and malformed results are not trusted graph assets.

## Resource controls

The integration must retain Sh4q's external-adapter controls: bounded version
probe, process timeout, output limit, isolated working directory, explicit
provenance, and scan ownership. A provider timeout is a partial stage result,
not a scan-wide failure.

## Release gate

The live CLI option should be enabled only after provider terms are reviewed,
an end-to-end offline test covers execution and scope filtering, and HTML,
JSON, and CSV reports visibly distinguish historical URLs from live endpoints.

The initial opt-in command is `sh4q scan example.com --url-history`. It looks
for `waybackurls` on `PATH`, applies a bounded 60-second process timeout, and
does not run discovered HTTP probing merely because historical URLs were found.

Trusted URL-history assets are capped at 2,000 per scan by default to prevent a
large archive from monopolizing local SQLite persistence. Complete provider
stdout remains durable adapter evidence, and a truncation notice is retained.
The URL-history runner permits up to 8 MB of provider output; this is a finite
bound that allows large archives to reach the 2,000 trusted-URL cap without
retaining unbounded subprocess output.
Accepted URL-history nodes, relationships, and scan ownership are persisted in
bounded batches when SQLite storage is available; each URL is still scope
validated before inclusion.

When sharing URL-history results, generate an export with `--redact`. This masks
known secret-like query keys and removes fragments without altering the local
database or evidence records.
