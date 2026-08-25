# sh4q Architecture and Product Direction

## Direction

sh4q is being developed as a safety-first reconnaissance control plane, not as a feature-for-feature replacement for reconFTW. Its value is coordinating discovery tools while enforcing scope, preserving provenance, surviving interruption, and producing reviewable evidence.

The project must not advertise itself as “trustworthy” or “scope-enforced” until the controls below are implemented and covered by regression tests. The current redirect behavior is a release blocker: an HTTP request can follow a redirect to an unauthorized host before the discovery handler performs its post-request check.

## Core Invariants

Every outbound operation must satisfy all of these conditions before it occurs:

1. The destination matches the configured scope and exclusions.
2. The destination’s resolved IP is allowed; private, loopback, link-local, multicast, and otherwise reserved addresses are denied unless explicitly supported by policy.
3. The port and request are admitted by the rate, concurrency, and total-budget controls.
4. Redirects are validated one hop at a time. No client may automatically follow an unvalidated redirect.
5. The operation and its decision are recorded with source plugin, target, timestamp, and tool/version context.

Discovery validation and request accounting are separate concerns. A scope policy answers “may this destination be contacted?” A limiter answers “may this request run now?” Asset discovery must not consume network budget merely because it is being validated.

## Target Architecture

The existing package boundaries remain useful, but network access should move behind shared services:

- `scope/`: normalized hostname/IP/port policy and explicit allow/deny decisions.
- `network/` (new): scoped DNS resolution, HTTP client, redirect handling, private-IP checks, and request admission.
- `limits/` (new or folded into `network/`): semaphore, requests-per-second limiter, and request budget.
- `plugins/`: discovery logic; plugins request operations through scoped services rather than constructing unrestricted clients.
- `events/`: durable event state machine with retry count, failure/dead-letter state, and graceful shutdown.
- `storage/`: transactional SQLite repositories, WAL/busy-timeout configuration, schema versioning, nodes, relationships, evidence, and provenance.
- `application/`: scan lifecycle, recovery, reporting, and CLI orchestration.

External tools should be added through a subprocess adapter that uses argument arrays (never shell strings), timeouts, output limits, sanitized environments, exit-status handling, and captured tool versions.

Discoveries should distinguish confidence states such as `DISCOVERED`, `RESOLVED`, `REACHABLE`, and `VERIFIED`; a certificate record is not evidence that a host is live.

## Required Remediation and Test Gates

### Gate 1: Safety boundary

- Disable automatic HTTP redirects.
- Validate every redirect destination before following it.
- Resolve and validate destination IPs, including DNS rebinding protection.
- Normalize lowercase/trailing-dot/IDNA hostnames.
- Enforce allowed ports and deny reserved address ranges by default.

Tests must use local fake DNS/HTTP servers and assert that unauthorized redirects, rebinding, ports, and reserved IPs are never contacted.

### Gate 2: Reliability

- Make event dispatch exception-safe; always call `task_done()`.
- Preserve failed events for retry or dead-letter handling.
- Add graceful cancellation and shutdown.
- Isolate plugin cleanup failures.
- Add crash/recovery tests for handler failure, duplicate delivery, and restart.

### Gate 3: Enforced controls

- Implement configured concurrency, request-rate, and total-request limits.
- Define and test whether retries consume budget.
- Add metrics for admitted, denied, retried, and blocked requests.

### Gate 4: Engineering quality

- Replace print-only tests with assertions and deterministic fakes.
- Add CI for supported Python versions, linting, type checking, and offline tests.
- Add SQLite transactions, WAL, busy timeout, and migration/version checks.
- Document threat model, plugin contract, configuration, and known limitations.

## Delivery Plan

Work in small, reviewable increments. Each increment must add regression tests before expanding discovery breadth. Do not add active scanners until the safety boundary and event guarantees pass their gates.

## Realistic Timeline

For one motivated developer working part-time (8–12 hours/week):

- **2–4 weeks:** redirect/IP safety boundary, hostname normalization, and regression tests.
- **2–3 weeks:** durable event failure handling, shutdown, retries, and recovery tests.
- **2–3 weeks:** real rate/concurrency/budget controls and metrics.
- **3–5 weeks:** storage hardening, schema versioning, CI, documentation, and CLI/reporting cleanup.
- **4–8 weeks:** first high-quality external-tool adapter and integration tests.
- **2–4 months afterward:** additional adapters, scheduling, exports, and usability improvements.

A credible, defensible beta could therefore take roughly **3–5 months part-time**. A substantial product with several maintained adapters, polished reporting, and operational documentation is more realistically **6–12 months**. These estimates assume disciplined scope; attempting to match reconFTW’s breadth would extend the project indefinitely.

## Release Positioning

Before the safety gates pass, describe sh4q as an experimental orchestration framework. Afterward, advertise the narrower and defensible claim: **policy-controlled, resumable reconnaissance orchestration with evidence provenance**. Publish limitations and a threat model alongside benchmarks; credibility is part of the product.
