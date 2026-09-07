# Virtual-host discovery design

This document defines a possible, opt-in virtual-host discovery slice. It is
design work only: it does not add a CLI flag, generate candidates, or make
network requests. Implementation requires a separate feature branch, offline
tests, and a reviewed pull request.

## Purpose and boundary

Virtual-host discovery tests whether an already authorised server responds
differently when presented with an alternate `Host` value. It is distinct from
subdomain enumeration: a candidate is not a trusted hostname merely because a
server returned an HTTP response for it.

The first version must not perform implicit dictionary generation or broad
Internet scanning. It should accept an operator-supplied candidate file (for
example, `--vhosts-file`) and require an explicit `--vhosts` opt-in. A later
proposal may permit candidates derived from scan-owned passive names, but that
must remain a separate policy decision.

## Authorization and scope

- Gate 1 must allow the original target and the operator must separately
  confirm written permission for virtual-host testing.
- The candidate file is input, not authorization. Every candidate is
  normalized and checked against the configured scope before a request.
- Gate 2 runs before persistence as a trusted asset. Out-of-scope candidates
  may be retained only as evidence of a rejected candidate; they must not
  trigger DNS/HTTP requests or become scan-owned assets.
- Requests use only the explicitly configured scheme and port. Redirect
  destinations are checked independently and are never implicitly trusted.
- Private, loopback, link-local, multicast, and otherwise reserved addresses
  remain blocked unless an explicit, documented lab policy allows them.

## Candidate and request limits

The adapter must fail closed when limits are absent or invalid. Initial
defaults should be conservative and configurable in the scan policy:

- maximum candidates: 500;
- one or two explicitly configured base endpoints (no automatic port sweep);
- maximum concurrency: 2;
- request rate: no more than 1 request/second per target;
- total request budget: 500 candidate requests, counted before dispatch;
- connect/read/overall timeout: 5/10/15 seconds;
- one retry for transient transport failures, with bounded jittered backoff;
- response body capture: headers plus at most 64 KiB, never execute returned
  content.

The scheduler must account for admitted, completed, failed, and budget-denied
requests. A timeout, cancellation, or output limit must produce durable
execution evidence and must not prevent already captured observations from
being retained as degraded/partial results.

## Probe and comparison strategy

For each candidate, send a normal HTTP request to the authorised endpoint
while setting the candidate `Host` header (and SNI only when explicitly
configured and authorised). Do not follow redirects automatically during the
probe; record the `Location` value and apply scope checks before any optional
follow-up.

A response is an observation, not proof of a virtual host. To reduce default
vhost false positives, record and compare:

- status code and effective URL;
- content length and a bounded body hash;
- selected headers (content type, server, location);
- normalized title or other small, deterministic fingerprints.

The baseline response for the same endpoint must be collected once with its
normal host. Candidates whose fingerprint is equivalent to the baseline are
labelled `default_vhost_match`; they are not reported as verified virtual
hosts. Differences are labelled `candidate_observation` until corroborated by
an independent signal. Duplicate candidates and equivalent normalized hosts
are suppressed while retaining provenance.

## Evidence and provenance

Every candidate, including rejected and failed ones, receives evidence with:

- source (`vhosts-file`), source line or record identifier, and scan ID;
- normalized candidate, endpoint, scheme, port, and timestamp;
- authorization decision and reason;
- request outcome, status, redirect, bounded fingerprint, and error class;
- adapter version/configuration hash and limit counters.

Only in-scope, successfully observed candidates may create scan-owned assets,
and their ownership source must be `vhost-discovery`. Raw responses remain
bounded evidence and must not include credentials or unbounded bodies.

## Failure handling and operator UX

Missing candidate files, malformed hostnames, unavailable adapters, and limit
violations should fail before dispatch with an actionable message. Per-
candidate DNS failures, connection errors, TLS errors, HTTP errors, and
timeouts should be recorded and allow the bounded scan to continue. The stage
summary must show candidates admitted, rejected, observed, default-vhost
matches, verified/differing observations, failures, and budget denials.

The dependency doctor should report the vhost capability only if an external
provider is ever introduced. A native implementation must not require a new
binary.

## Test-first implementation gate

Before any live implementation is merged, add deterministic offline fixtures
covering normalization, scope/Gate 2 rejection, candidate and request bounds,
baseline comparison, redirects, duplicate suppression, timeout/retry evidence,
partial completion, and persistence ownership. Scheduler tests must assert that
out-of-scope candidates never reach the request layer. A local HTTP fixture may
be used for response comparison; no public target is needed for CI.

## Explicit non-goals

This slice does not brute-force arbitrary names, scan additional ports, probe
private addresses, execute JavaScript, submit forms, validate credentials, or
turn a response into a security finding. Those capabilities require separate
authorization and product decisions.
