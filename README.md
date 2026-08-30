# Sh4q

Sh4q is a policy-controlled reconnaissance orchestration prototype for authorised domain discovery. It combines scope checks, DNS and HTTP verification, durable evidence, scan-specific results, exports, and conservative technology observations.

It is a research prototype. It is not a vulnerability scanner, an exploitation framework, or a replacement for mature reconnaissance suites.

## Quick Start

Requirements: Linux, Python 3.11 or newer, and Git. Subfinder is optional.

```bash
git clone <repository-url>
cd sh4q
python3 -m venv venv
source venv/bin/activate
python -m pip install -e .
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
sh4q export --latest --target your-domain.example \
  --alive http --format csv --output alive.csv
```

## Read Before Testing

- [Installation](docs/installation.md)
- [Quick start](docs/quickstart.md)
- [Authorised use](docs/authorized_use.md)
- [Threat model](docs/threat_model.md)
- [Known limitations](docs/limitations.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Testing](docs/testing.md)
- [Feedback guide](docs/feedback.md)

The default database is `./sh4q-output/sh4q.db`. It may contain sensitive target data and must not be committed or shared without review.

## Current Capabilities

- Gate 1 target authorisation and Gate 2 discovery validation.
- Reserved/private address controls and redirect validation.
- DNS, HTTP, certificate-transparency, and optional Subfinder discovery.
- Bounded discovered-host DNS and HTTP enrichment.
- Durable events, retries, interruption handling, and evidence storage.
- Per-scan ownership, results, scan overview, JSON/CSV export, and liveness filters.
- Conservative native technology observations from already-authorised HTTP responses.
- A deterministic offline suite used by CI.

## Project Status

Sh4q is approaching a private alpha for trusted testers. Expect incomplete packaging, variable live-provider results, and breaking changes between early versions.
