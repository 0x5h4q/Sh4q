# v2 Phase 1: JavaScript Extraction

This is the acceptance contract for the first v2 feature. It extends Sh4q's
passive, evidence-first workflow without changing the v1 scope or persistence
invariants.

## Goal

Extract useful client-side references from already-authorised HTTP responses:

- script URLs;
- same-scope API and endpoint references found in JavaScript or HTML;
- explicitly labelled secret-like patterns for review, never as confirmed
  credentials.

The feature is an observation stage. It must not execute JavaScript, submit
forms, brute-force paths, or contact a newly extracted destination implicitly.

## Input Contract

Only scan-owned, successful HTTP observations from the current scan may be
analysed. Inputs are bounded by:

- a configurable maximum response sample size;
- a maximum number of endpoints per response;
- a maximum number of scripts per page;
- a maximum script size;
- a total extraction time limit per scan.

The extractor receives response metadata and bounded content already collected
by the HTTP pipeline. It does not make an independent network request in the
initial implementation.

## Scope Contract

Every extracted URL, hostname, and candidate endpoint is normalised and passed
through the same scope engine before it can become a trusted asset or
relationship. Out-of-scope, malformed, private, and reserved destinations are
retained only as denied evidence.

An extracted string is never treated as live. A later, explicitly enabled
stage must perform DNS or HTTP verification under its own request budget.

## Evidence Contract

Each observation must retain:

- source scan and source HTTP endpoint;
- extractor name and version;
- observation type (`script_url`, `endpoint_reference`, or
  `secret_like_pattern`);
- a redacted or hashed value where the raw value could contain a credential;
- a short location/context excerpt with strict size limits;
- pattern name and confidence for secret-like matches;
- scope decision and rejection reason where applicable.

Secret-like matches are leads for human review. Reports must state clearly that
they may be placeholders, public identifiers, test values, or false positives.

## Safety Requirements

- No JavaScript execution.
- No automatic requests to extracted URLs.
- No credential validation or authentication attempts.
- No shell invocation or external interpreter.
- Deterministic pattern matching with bounded regular expressions.
- Redaction before shared exports; local evidence must still follow the
  repository's sensitive-data handling rules.
- Repeated events must be idempotent.

## Acceptance Tests

The implementation is ready when offline fixtures prove that it:

1. extracts same-scope script and endpoint references;
2. rejects and records an out-of-scope reference without contacting it;
3. rejects private and reserved destinations;
4. enforces response, script, result, and time limits;
5. labels secret-like values without claiming they are valid credentials;
6. records source endpoint, extractor version, context, and scope decision;
7. produces stable deduplicated relationships on repeated delivery;
8. leaves v1 results and exports unchanged when the stage is not enabled.

## Delivery Slices

1. Add pure extraction functions with deterministic fixtures.
2. Add a plugin that consumes existing HTTP observations only.
3. Add scope-aware persistence and evidence handling.
4. Add an opt-in CLI flag and stage summary.
5. Add HTML, JSON, and CSV presentation with explicit confidence language.
6. Run the full offline suite and one authorised acceptance scan with the stage
   disabled and enabled.

The feature remains opt-in until all acceptance tests, redaction checks, and
resource-limit tests pass.
