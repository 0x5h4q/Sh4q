# Sh4q Private Alpha Guide

Sh4q is a policy-controlled reconnaissance tool for domains you own or are explicitly authorised to test. It records what it observed, where the observation came from, and why a request or result was accepted or rejected.

## Install

```bash
git clone <repository-url>
cd sh4q
python3 -m venv venv
source venv/bin/activate
python -m pip install -e .
```

Subfinder is optional. The normal scan works without it. Add it only when you want passive subdomain discovery:

```bash
sh4q scan your-authorized-domain.example --sub
```

## First Scan

```bash
sh4q scan your-authorized-domain.example
```

The scan runs DNS, HTTP, and certificate-transparency checks. With `--sub`, it also runs Subfinder and probes discovered names only after DNS and scope checks succeed.

## Read Results

```bash
sh4q show --latest --target your-authorized-domain.example
sh4q results --latest --target your-authorized-domain.example --type domain
sh4q results --latest --target your-authorized-domain.example --type url
sh4q results --latest --target your-authorized-domain.example --type technology
sh4q results --latest --target your-authorized-domain.example --failures
```

HTTP status codes such as `403` and `404` mean that a server responded. They do not mean that access was granted or that the application is healthy.

## Export

```bash
sh4q export --latest --target your-authorized-domain.example --format csv --output results.csv
sh4q export --latest --target your-authorized-domain.example --alive dns --format csv --output dns-alive.csv
sh4q export --latest --target your-authorized-domain.example --alive http --format csv --output http-alive.csv
sh4q export --latest --target your-authorized-domain.example --type technology --format json --output technologies.json
sh4q export --latest --target your-authorized-domain.example --type http-inventory --format csv --output http-inventory.csv
```

Exports are complete scan views and are not limited by the number shown in the terminal. Existing files are protected; use `--force` only when replacement is intentional.

## Feedback

Please report the Sh4q version, command used, scan ID, operating system, and the problem you saw. Remove credentials, private hostnames, tokens, and sensitive response data before sharing logs or exports.

## Current Boundaries

Sh4q is an early research prototype, not a vulnerability scanner or exploitation framework. Provider outages, rate limits, DNS timeouts, HTTP blocks, and changing public data can affect live results. The database and exports may contain sensitive target information.
