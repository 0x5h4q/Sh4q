# Contributing to Sh4q

Thank you for helping improve Sh4q. It is an early open-source review release,
so contributions should preserve its focus: authorised, discovery-only
reconnaissance with clear scope decisions, evidence, provenance, and recovery.

## Good First Contributions

- Bug fixes, documentation corrections, and report usability improvements.
- Deterministic offline tests and regression cases.
- Reliability fixes that preserve request accounting and evidence semantics.
- Adapter parsing or lifecycle improvements with bounded execution and tests.

## Before Opening a Pull Request

1. Explain the user-visible problem and the intended behavior.
2. Keep changes focused and follow the existing Python style and module
   boundaries.
3. Add or update an executable test under `tests/` for behavioral changes.
4. Run the relevant test scripts and, when practical, the full offline suite:
   `python tools/run_offline_tests.py`.
5. Clearly identify any network-dependent checks and use only targets you own
   or are explicitly authorised to test.
6. Do not include databases, scan exports, credentials, private target data,
   virtual environments, or generated build files.

## Safety Boundaries

Changes that broaden target contact, weaken scope enforcement, bypass Gate 2,
add exploitation or credential testing, or introduce active scanners require a
separate policy review and should be proposed before implementation. External
adapters must retain argument allow-lists, bounded timeouts, output limits,
controlled environments, provenance, and evidence-first handling.

Pull requests are reviewed on correctness, safety, test coverage, and whether
the change fits the documented v1 scope. Maintainers may defer broad features
to a post-v1 milestone.
