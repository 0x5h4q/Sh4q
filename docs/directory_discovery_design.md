# Directory and content discovery design

This document defines a possible, opt-in directory/content discovery slice.
It is design work only: it does not add a CLI flag, probe paths, or introduce
an external scanner. Implementation requires a separate branch, offline tests,
and a reviewed pull request.

## Purpose and boundary

Directory discovery checks a bounded set of operator-supplied paths beneath an
already authorised HTTP origin. It identifies responses worth reviewing; it
does not exploit endpoints, submit forms, mutate state, or claim that a path is
a vulnerability.

The initial version must require explicit `--directories` opt-in and an
operator-supplied wordlist (for example, `--directories-file`). It must never
generate or download an implicit large dictionary. Candidates are relative
paths only; absolute URLs, alternate hosts, and port changes are rejected.

## Authorization and scope

- Gate 1 must allow the original target and the operator must confirm written
  permission for active content discovery.
- The candidate file is input, not authorization. The base origin and every
  redirect destination are independently checked by the scope engine.
- Gate 2 runs before persistence. Out-of-scope or malformed paths may remain
  as rejection evidence but must not trigger a request or become assets.
- Requests use only explicitly configured HTTP/HTTPS scheme and allowed port.
- Reserved, private, loopback, link-local, multicast, and unspecified
  addresses remain denied unless a documented lab policy allows them.

## Candidate and request limits

The adapter must fail closed when limits are absent or invalid. Initial
defaults should be conservative and policy-configurable:

- maximum paths: 200;
- maximum path length: 512 bytes;
- maximum concurrency: 2;
- request rate: no more than 1 request/second per origin;
- total request budget: 200, counted before dispatch;
- connect/read/overall timeout: 5/10/15 seconds;
- at most one retry for transient transport failures;
- response headers plus at most 32 KiB of body for comparison;
- no recursive crawling and no automatic port or scheme expansion.

The scheduler must report admitted, completed, failed, and budget-denied
requests. Timeouts, cancellation, and output limits produce durable evidence
and retain already captured observations as partial/degraded results.

## Probe and false-positive handling

Normalize each candidate as a URL path: accept `/admin` or `admin`, collapse
duplicate slashes and dot segments, reject control characters, fragments,
credentials, query strings unless explicitly enabled by a future policy, and
paths that escape the origin. Duplicate normalized paths are probed once.

Collect one baseline request for the origin and compare each candidate using:

- status code;
- effective URL and redirect location;
- content type and bounded content length;
- bounded body hash and normalized title;
- a configurable “not found” fingerprint.

Responses equivalent to the baseline 404/default response are labelled
`not_found_match`, not as discovered content. Distinct responses are labelled
`candidate_observation` until reviewed. Redirects are recorded without
automatic follow-up; any optional follow-up must re-run authorization.

## Evidence and provenance

Every candidate, including malformed, rejected, duplicate, and failed entries,
receives evidence containing:

- source (`directories-file`), source line, and scan ID;
- normalized path and base endpoint;
- authorization decision and rejection reason;
- request outcome, status, redirect, bounded fingerprint, and error class;
- adapter version/configuration hash and limit counters.

Only in-scope observations may create scan-owned assets. Their ownership source
must be `directory-discovery`; raw bodies remain bounded evidence and must not
contain credentials or unbounded content.

## Failure handling and operator UX

Missing files, invalid encodings, malformed paths, unsupported schemes, and
limit violations should fail before dispatch with an actionable message.
Per-path DNS, connection, TLS, HTTP, and timeout errors should be recorded and
allow the bounded stage to continue. The stage summary should distinguish
paths admitted, rejected, duplicated, observed, not-found matches, failures,
and budget denials.

An external tool such as ffuf must not be enabled through a generic adapter
flag. If a provider is added later, it needs its own doctor entry, argument
allow-list, output bound, and explicit packet/rate disclaimer.

## Test-first implementation gate

Before live implementation is merged, add deterministic offline fixtures for
path normalization, traversal and query rejection, scope and Gate 2 handling,
candidate/request bounds, baseline comparison, redirects, duplicate
suppression, timeout/retry evidence, partial completion, persistence ownership,
and HTML/terminal presentation. Scheduler tests must assert that rejected
paths never reach the request layer. A local HTTP fixture is sufficient for all
CI behavior.

## Explicit non-goals

This slice does not brute-force arbitrary paths, recurse through discovered
content, scan extra ports, probe private addresses, execute JavaScript, submit
forms, validate credentials, or turn a response into a security finding.
