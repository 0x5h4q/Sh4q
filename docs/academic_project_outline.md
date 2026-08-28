# Design and Implementation of a Scope-Controlled Reconnaissance Orchestration and Evidence Management System

## Document Status

This is a working academic draft derived from the Sh4q engineering record. Institutional details, supervisor-approved research wording, citations, final evaluation data, screenshots, and page numbering must be completed before submission.

## Front Matter Placeholders

- Student name: `[INSERT FULL NAME]`
- Registration number: `[INSERT REGISTRATION NUMBER]`
- Department and college: `[CONFIRM OFFICIAL WORDING]`
- Supervisor: `[INSERT SUPERVISOR NAME]`
- Submission month and year: `[INSERT DATE]`
- Certification, dedication, acknowledgements, table of contents, lists of figures/tables, abbreviations, and abstract.

# CHAPTER ONE: INTRODUCTION

## 1.1 Background to the Study

Cybersecurity reconnaissance is the process of collecting information about publicly reachable systems, domains, services, and related infrastructure before deeper security assessment. Existing reconnaissance tools can discover large volumes of information, but their operational focus is commonly breadth and speed. In authorised environments, discovery must also remain within an approved scope, survive interruptions, retain evidence, and explain how each asset entered the result set.

Sh4q is proposed as a scope-controlled reconnaissance orchestration and evidence management system. Rather than replacing mature discovery utilities, it provides an execution layer that authorises targets, coordinates plugins, records durable events, normalises assets, and preserves raw observations. Its design addresses the difference between discovering an item and accepting that item as an authorised asset.

## 1.2 Statement of the Problem

Reconnaissance automation can contact unintended hosts through redirects, unsafe name resolution, over-broad configurations, or inconsistent plugin behaviour. It can also lose results after interruption, duplicate recovered work, obscure provider failures, and mix raw observations with verified assets. These weaknesses reduce auditability and can create ethical, legal, and operational risks.

There is therefore a need for a reconnaissance orchestration system that treats scope enforcement, destination safety, evidence provenance, durable processing, and failure reporting as central system requirements rather than optional plugin behaviour.

## 1.3 Aim and Objectives

The aim is to design, implement, and evaluate a scope-controlled reconnaissance orchestration and evidence management system.

The objectives are to:

1. design a modular architecture for authorised reconnaissance workflows;
2. implement hostname, IP address, port, redirect, and destination-safety controls;
3. implement plugin scheduling, durable event handling, asset normalisation, and evidence storage;
4. evaluate correctness using deterministic regression, crash-recovery, and controlled integration tests;
5. assess the system's limitations and suitability as a foundation for auditable reconnaissance automation.

## 1.4 Methodology Overview

The project follows an iterative design-and-build methodology. Requirements are derived from reconnaissance safety and reliability problems. The system is implemented in Python using asynchronous components, Pydantic configuration models, HTTPX networking, and SQLite persistence. Each architectural invariant is validated with focused tests before discovery breadth is expanded.

## 1.5 Significance of the Study

The study demonstrates how security tooling can prioritise authorisation, provenance, failure recovery, and transparent reporting. It contributes a practical architecture for students, researchers, consultants, and security teams that require controlled reconnaissance rather than an opaque collection of tool executions.

## 1.6 Scope and Limitations

The current system is discovery-only. It supports DNS resolution, HTTP probing, and certificate-transparency discovery. It does not exploit vulnerabilities, crawl applications, perform broad port scanning, or compete with mature reconnaissance suites in discovery breadth. Rate limits, durable failure states, CI, database migrations, and external-tool adapters remain planned work.

## 1.7 Organisation of the Study

Chapter One introduces the problem. Chapter Two reviews related concepts and tools. Chapter Three presents system analysis, design, and methodology. Chapter Four describes implementation and evaluation. Chapter Five summarises the study, limitations, recommendations, and conclusions.

# CHAPTER TWO: LITERATURE REVIEW

## 2.1 Preamble

This chapter will review authorised reconnaissance, attack-surface management, scope control, certificate transparency, asynchronous orchestration, event-driven systems, evidence provenance, and resilient automation.

## 2.2 Conceptual Foundation

The conceptual model separates four concerns: policy determines whether a destination is allowed; network controls determine how it may be contacted; plugins produce observations; and persistence preserves both raw evidence and normalised asset state.

## 2.3 Reconnaissance Techniques

Discuss passive discovery, DNS resolution, HTTP probing, certificate-transparency logs, active discovery, and ethical boundaries. Distinguish discovery from verification and exploitation.

## 2.4 Scope Enforcement and SSRF-Related Risks

Review hostname scope, CIDR policy, redirect validation, private/reserved address protection, DNS rebinding, port restrictions, and the importance of checking a destination before network contact.

## 2.5 Event-Driven and Resumable Systems

Review asynchronous queues, at-least-once delivery, idempotency, durable event logs, retries, dead-letter handling, and graceful shutdown.

## 2.6 Evidence Provenance and Asset Normalisation

Explain the two-truths model: immutable observations provide provenance, while mergeable graph records represent current asset state.

## 2.7 Review of Existing Tools

Compare reconFTW, Amass, Subfinder, httpx, and related systems using breadth, scope policy, durability, provenance, extensibility, and reporting. Sh4q should be positioned as an orchestration control plane, not as a direct breadth competitor.

## 2.8 Identified Gap

The research gap is the limited emphasis on centralised, testable scope enforcement and durable evidence handling across heterogeneous reconnaissance operations.

## 2.9 Literature Review Requirements

This chapter requires supervisor-approved scholarly sources, APA 7 citations, a comparison table, and a literature matrix covering approximately 2020-2026. Tool documentation may support implementation discussion but should not replace peer-reviewed literature. The documented collection workflow in `docs/research_workflow.md` uses OpenAlex/Crossref for candidate discovery, publisher/library records for verification, Zotero as the citation source of record, and NotebookLM only for synthesis.

# CHAPTER THREE: SYSTEM ANALYSIS, DESIGN AND METHODOLOGY

## 3.1 Existing-System Analysis

Existing workflows often chain utilities through shell scripts. They provide strong coverage but can distribute scope decisions, retries, parsing, and evidence handling across unrelated tools.

## 3.2 Proposed System

Sh4q centralises scan lifecycle management. The application layer loads configuration and starts recovery; the Scope Engine authorises targets; scoped network services validate destinations; the Scheduler orders plugins; the Event Bus transports durable discoveries; handlers record evidence and update the asset graph; and the CLI reports results.

## 3.3 Functional Requirements

- Accept a target and optional YAML configuration.
- Reject unauthorised targets before plugin execution.
- Validate ports, redirects, resolved addresses, and private-address policy.
- Execute dependency-ordered plugins with bounded timeouts and retries.
- Store evidence, nodes, relationships, and durable event status.
- Recover unfinished events without duplicating evidence or relationships.
- Report assets separately from operational evidence.

## 3.4 Non-Functional Requirements

Safety, auditability, modularity, recoverability, deterministic testing, understandable failure reporting, and controlled extensibility.

## 3.5 Architecture

Document Gate 1 target authorisation, scoped HTTP resolution and IP pinning, per-redirect checks, plugin execution, durable event publication, evidence-first handling, Gate 2 asset acceptance, and SQLite persistence. Include component, sequence, data-flow, and deployment diagrams.

## 3.6 Data Design

Describe Node, Relationship, Evidence, and Event Log records. Explain deterministic identifiers and idempotent inserts.

## 3.7 Methodology

Use iterative prototyping with test-backed increments. Record the discovered defects: unsafe automatic redirects, hostname/IP policy confusion, request-budget coupling, dispatcher failure risk, CT provider instability, retry data loss, misleading counts, URL duplication, and timeout cancellation. Explain how each defect changed the design.

## 3.8 Ethical and Security Considerations

Testing must use owned, permitted, or controlled targets. Private addresses are denied by default. Live-domain observations are limited to low-impact discovery and should be documented as engineering validation, not proof of authorisation for intrusive testing.

# CHAPTER FOUR: SYSTEM IMPLEMENTATION AND EVALUATION

## 4.1 Implementation Environment

Python 3.11+, asyncio, Pydantic v2, PyYAML, aiosqlite, HTTPX, SQLite, setuptools, and a command-line interface.

## 4.2 Implemented Components

Describe configuration loading, Scope Engine, scoped HTTP transport, DNS plugin, HTTP plugin, CT connectors, Scheduler, Event Bus, Durable Event Log, Evidence Store, graph storage, handlers, scan runner, and CLI.

## 4.3 Important Engineering Corrections

1. Automatic redirect following was replaced with hop-by-hop policy checks.
2. DNS answers are checked for unsafe address classes and the approved IP is pinned to the connection while preserving Host and TLS SNI.
3. Scope authorisation was separated from future request accounting.
4. Public DNS answers are evaluated by address-safety policy rather than literal hostname-scope matching.
5. HTTP/HTTPS results are isolated and timeout evidence is preserved before the scheduler's hard deadline.
6. CT partial results survive provider degradation, retries, and rate limiting.
7. Asset counts are separated from evidence and provider-status events.
8. Equivalent URLs are canonicalised before persistence.
9. One scan-wide request limiter now enforces concurrency, pacing, and total budget at the HTTP transport boundary.
10. Scope validation does not consume request budget; each real redirect, fallback-IP, pagination, or retry attempt does.
11. Request-limit configuration and observed counters are persisted as a `request_metrics` evidence record for each scan outcome.
12. External-tool integration begins with a restricted adapter contract using shared policy services and argument arrays rather than shell command strings.
13. A controlled subprocess runner bounds executable choice, environment, runtime, output, cancellation, and process cleanup before adapter output is accepted.
14. Adapter execution details and raw output are preserved as evidence, while parsed assets pass through the existing Gate 2 policy before graph storage.
15. The native Python request limiter is not misrepresented as control over packets generated inside external tools; stronger enforcement requires tool-specific restrictions and eventual OS-level containment.
16. The first real adapter is a passive, opt-in Subfinder integration exposed as `--sub`, with fixed arguments, an isolated configuration home, controlled execution evidence, deduplication, and Gate 2 validation. An offline scheduler test validates the complete orchestration path without internet access.
17. A live adapter run exposed overlap inflation between CT and Subfinder observations. Per-source counts are retained, but total assets and relationships now use unique identifiers; enumerated hostnames are not described as live endpoints without later resolution or probing.
18. Approved Subfinder names now enter a bounded discovered-DNS stage only after pre-resolution scope authorization; reserved resolved addresses are denied before asset storage. HTTP probing of discovered names remains a separate risk-controlled phase.
19. A live large-batch run exposed timeout/retry amplification and partial-result loss in discovered DNS. Per-name timeouts, bounded concurrency, partial preservation, and compact reporting were added; the formal evaluation should measure these under controlled loads.
20. A later zero-result run was traced through execution evidence to a Subfinder process timeout rather than a genuine absence of findings. Explicit adapter-failure reporting, a bounded 120-second allowance, and source-specific stage hand-off were added.
21. Large-run reporting now separates current-scan evidence from historical stored evidence, labels native request metrics accurately, and reports discovered-DNS failures for reproducible performance analysis.
22. A first non-SQL `results` interface lists stored domains, IPs, URLs, and target-filtered failures. Exact per-scan asset views remain dependent on first-class scan-run ownership.
23. Asset target filtering uses exact-domain/subdomain boundaries; target IP views traverse stored resolution relationships rather than mixing unrelated database assets.
24. Result limiting now occurs after target matching; a discovered pagination defect previously produced inconsistent counts when filtering a global limited row set.
25. Durable scan-run identity records target, start/completion time, and outcome for new executions. Historical runs are not backfilled with guessed identities; evidence and asset ownership migration remains the next step.
26. New evidence and accepted graph relationships now retain scan-run ownership, allowing exact run and latest-run result views while preserving the deduplicated global asset graph.
27. Exact scan exports support structured JSON and spreadsheet-compatible CSV, include scan metadata and source provenance, avoid interactive result limits, and protect existing files from accidental overwrite.
28. Export detects migration-era runs that lack asset ownership and refuses misleading empty output; latest-run selection excludes unfinished executions while retaining them in the audit list.
29. A live migration validation found and corrected a scan-ownership handler defect: counters could report accepted assets before per-scan ownership persistence succeeded. Exact results and export exposed the inconsistency; ownership is now written before counters are updated, with regression coverage. The affected historical run is excluded from exact export rather than guessed or backfilled.
30. Structured export supports an evidence-backed HTTP liveness view (`--alive http`), selecting domains with a scan-owned HTTP/HTTPS endpoint observation rather than treating passive discovery as proof of availability.
31. Live export validation corrected an ownership-query assumption: HTTP liveness is derived from the scan-owned URL and `SERVES` relationship, and an empty filtered result is distinguished from an ownership-migration failure by checking the unfiltered ownership count.
32. HTTP-alive exports include the responding endpoint and status code, allowing the evaluation to verify the classification from stored evidence.
33. DNS-alive exports provide one row per domain and permitted resolved address, distinguishing DNS liveness from HTTP liveness.
34. A controlled discovered-HTTP enrichment stage probes only in-scope names with successful DNS observations, producing auditable HTTP status and endpoint evidence for liveness evaluation.
35. Live testing showed that public DNS timeouts can leave the enrichment stage with no eligible names; the system reports these failures and safely sends no HTTP requests. Offline fixtures provide repeatable validation independent of external DNS conditions.
36. A simple reachability utility such as `httprobe` was evaluated conceptually but deferred as an adapter because Sh4q's native HTTP enrichment already supplies equivalent probing plus scope, redirect, budget, and evidence controls. Any future comparison will use identical controlled inputs and repeated measurements.
37. Technology fingerprinting is planned as a separate enrichment stage over scan-owned HTTP endpoints. Fingerprints will preserve technology, category, version, detection method, confidence, tool provenance, timestamp, and raw evidence reference, and will be treated as observations rather than definitive version claims. Candidate tools will be selected only after controlled comparison.
38. ProjectDiscovery `httpx` was selected as the first parser-only fingerprinting candidate because it supplies structured JSONL. The candidate remains disabled in live scans until scan-owned endpoint input, redirect containment, and request-control implications are validated.
39. Offline fingerprint-pipeline validation shows that in-scope observations create normalized technology nodes and provenance-bearing relationships, while out-of-scope output remains evidence but is rejected from trusted asset state.
40. Technology observations can be queried through the non-SQL results interface by exact scan or target, completing the presentation path before live fingerprint execution is introduced.

## 4.4 Testing Strategy

Include deterministic scope tests, mocked redirect tests, reserved-address tests, mixed DNS-answer tests, IDNA tests, a local TLS integration test, HTTP partial-timeout tests, CT provider retry tests, evidence idempotency tests, and crash recovery tests.

## 4.5 Evaluation Metrics

- Scope-policy correctness.
- Number of forbidden network contacts in adversarial tests (target: zero).
- Recovery correctness and duplicate count (target: zero duplicates).
- Asset/evidence consistency.
- Provider partial-result retention.
- Scan duration and timeout behaviour.
- Request admissions, budget denials, failures, and peak concurrency.
- Test pass rate.

## 4.5.1 Research Reproducibility

Record database, query, search date, results reviewed, inclusion decisions, DOI verification, and source-to-claim links. Include the search manifest and literature matrix in an appendix. Automated metadata collection is an aid to discovery, not evidence that a source is scholarly or relevant.

## 4.6 Preliminary Results

Controlled tests demonstrate blocked out-of-scope redirects, reserved-address rejection, DNS-rebinding resistance through IP pinning, preserved TLS hostname identity, URL deduplication, retained CT partial results, bounded request concurrency, paced admissions, and budget denial before transport contact. A preliminary SQLite concurrency run completed 50 parallel synthetic work units in approximately 0.669 seconds and produced the expected 100 nodes, 50 relationships, 50 event-log records, and 50 evidence records without observed lock errors or lost writes. This single run is engineering evidence rather than a final benchmark; the thesis evaluation must repeat the experiment several times and report mean, median, minimum, maximum, and standard deviation. Live-domain runs exposed realistic DNS latency, HTTP timeout, CT degradation, and rate-limit conditions. These runs informed corrections but are not a substitute for controlled evaluation.

## 4.7 Current Limitations

Durable event retries, dead-letter handling, recovery, and clean interruption are implemented. Request-rate, concurrency, and total-budget controls are enforced for the current HTTP and CT paths, but future adapters still require a non-bypassable controlled-network contract and richer durable request metrics. SQLite schema migration and CI are absent. Tests remain a mixture of assertions and older executable scripts. Discovery breadth is intentionally limited. Gate 1 is functionally complete for the current DNS, HTTP, and CT paths, with follow-up hardening tracked in `architecture.md`. Stage output is ordered by draining each plugin stage before the next begins; interrupted plugin execution is still rerun rather than resumed at plugin-attempt granularity.

# CHAPTER FIVE: SUMMARY, RECOMMENDATIONS AND CONCLUSION

## 5.1 Summary

The project demonstrates a modular reconnaissance control plane centred on policy, evidence, and recovery rather than maximum discovery breadth.

## 5.2 Contributions

- A two-stage authorisation model.
- A scoped HTTP boundary with redirect and DNS-rebinding protection.
- Separation of evidence from normalised asset state.
- Durable event replay with idempotent persistence.
- Provider-aware partial-result preservation and transparent reporting.

## 5.3 Recommendations

Complete Gate 3 durable request accounting, adapter enforcement, and performance reporting, then add a human-friendly results/query interface, schema migration, CI, and formal repeated evaluation. Add external-tool adapters only through the controlled execution and networking contracts.

Python was retained for the academic implementation because the system is currently I/O-bound and benefits from asyncio, HTTPX, Pydantic, SQLite support, and rapid security-tool integration. Go offers stronger binary distribution and runtime efficiency, but a rewrite would not itself solve scope-policy, evidence, retry, or adapter correctness and would require complete regression revalidation. Reconsider the language only after profiling demonstrates a concrete limitation.

## 5.4 Conclusion

Sh4q provides a defensible foundation for authorised, auditable reconnaissance orchestration. Its contribution is not superior enumeration breadth but the central enforcement and evidence architecture through which specialised discovery tools can be coordinated safely.

The intended product is a policy and evidence control plane for attack-surface discovery. It can coordinate domain, API, certificate, cloud, and future mobile-backend discovery tools while preserving provenance and preventing unverified or out-of-scope observations from becoming trusted inventory.

## Appendices to Prepare

- Configuration examples.
- Architecture and sequence diagrams.
- Test-case matrix and outputs.
- Selected source-code listings.
- Database schema.
- Commit/change chronology.
- Ethical testing statement.
- User guide.
