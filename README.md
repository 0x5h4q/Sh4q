# Sh4q

<table><tr><td align="center" bgcolor="#f5f7f9"><img src="banner.png" alt="Sh4q" width="720"></td></tr></table>

<p align="center">
  <a href="https://github.com/0x5h4q/Sh4q/releases/tag/v0.1.0"><img src="https://img.shields.io/badge/release-v0.1.0-2c9c94.svg" alt="Release v0.1.0"></a>
  <a href="https://github.com/0x5h4q/Sh4q/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-167d76.svg" alt="MIT License"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11%2B-3776ab.svg" alt="Python 3.11+"></a>
  <a href="https://github.com/0x5h4q/Sh4q"><img src="https://img.shields.io/badge/platform-Linux-lightgrey.svg" alt="Linux"></a>
  <img src="https://img.shields.io/badge/offline%20tests-43%2F43-2ea043.svg" alt="43 of 43 offline tests passing">
</p>

**Policy-controlled reconnaissance with durable evidence and explainable scope decisions.**

Sh4q is a scope-aware reconnaissance orchestration tool for authorised domain
discovery. It combines centralized policy checks, DNS and HTTP verification,
certificate-transparency discovery, durable evidence, scan-specific results,
exports, and conservative technology observations.

It is a research prototype. It is not a vulnerability scanner, an exploitation framework, or a replacement for mature reconnaissance suites.

## Why Sh4q Exists

Tools such as reconFTW are optimized for breadth: they coordinate a large
number of enumeration, crawling, fuzzing, OSINT, and vulnerability-testing
utilities. Sh4q deliberately operates at a different layer. It provides a
scope and evidence control plane around discovery workflows so that each
accepted asset has an authorization decision, provenance, durable state, and
reviewable output.

Use reconFTW or other specialist tools when maximum collection breadth is the
goal. Use Sh4q when you need to understand what was contacted, why it was
accepted, what failed, and which observations are actually supported by
evidence. Sh4q can orchestrate selected external tools, but it does not claim
reconFTW's scanning breadth or replace active security testing.

## Quick Start

Requirements: Linux, Python 3.11 or newer, and Git. Subfinder is optional.

```bash
git clone <repository-url>
cd sh4q
python3 -m venv venv
source venv/bin/activate
python -m pip install -e .
```

For a globally available command with isolated dependencies, use `pipx`:

```bash
pipx install git+https://github.com/0x5h4q/Sh4q.git@v0.1.0
```

Scan a domain you own or are explicitly authorised to test:

```bash
sh4q scan your-domain.example
```

If Subfinder is installed:

```bash
sh4q scan your-domain.example --sub
```

Review the latest scan:

```bash
sh4q show --latest --target your-domain.example
sh4q results --latest --target your-domain.example --type url
sh4q results --latest --target your-domain.example --type technology
```

Export HTTP-responsive domains:

```bash
sh4q export --latest --target your-domain.example --alive http --format csv --output alive.csv
```

Generate a self-contained, offline-filterable HTML asset report:

```bash
sh4q export --latest --target your-domain.example --format html --output report.html
```

## Documentation

- [Installation](docs/installation.md)
- [Quick start](docs/quickstart.md)
- [Authorised use](docs/authorized_use.md)
- [Threat model](docs/threat_model.md)
- [Known limitations](docs/limitations.md)
- [v1 roadmap](docs/v1_roadmap.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Testing](docs/testing.md)
- [Feedback guide](docs/feedback.md)

The roadmap, threat model, and limitations are included for reviewers. The
continuation handoff and outreach pitch are maintained as project-internal
working documents and are not part of the public quick-start path.

The default database is `./sh4q-output/sh4q.db`. It may contain sensitive target data and must not be committed or shared without review.

## Current Capabilities

- Gate 1 target authorisation and Gate 2 discovery validation.
- Reserved/private address controls and redirect validation.
- DNS, HTTP, certificate-transparency, and optional Subfinder discovery.
- Optional passive Amass discovery and ProjectDiscovery HTTPX enrichment.
- Bounded discovered-host DNS and HTTP enrichment.
- Durable events, retries, interruption handling, and evidence storage.
- Per-scan ownership, results, scan overview, JSON/CSV export, and liveness filters.
- Conservative native technology observations from already-authorised HTTP responses.
- A deterministic offline suite used by CI.
- A self-contained HTML asset report with client-side filters for type, host,
  status, technology/category, source, and text search.

## Project Status

Sh4q `v0.1.0` is available as a limited review release for trusted testers.
Expect variable live-provider results and the documented limitations
around completeness, active scanning, and external-tool availability. Passive
Amass support is experimental and optional.

Sh4q is released under the [MIT License](LICENSE).
