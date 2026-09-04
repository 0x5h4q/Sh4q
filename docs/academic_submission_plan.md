# Academic Submission Plan

The Sh4q repository will continue evolving after the v1 review release. The
academic project should therefore define a reproducible thesis snapshot rather
than attempt to describe every later repository change.

## Version strategy

- Treat `v0.1.0`/v1 as the validated baseline implementation.
- Continue v2 development as a separate engineering phase.
- Select and record a thesis snapshot before final evaluation, ideally 8-12
  weeks before submission.
- Tag or archive that snapshot locally with its commit, dependency lockfile,
  database schema version, test output, configuration, and report fixtures.
- Do not silently replace evaluation results when later features change.

## Thesis scope options

The strongest thesis scope is the policy and evidence control plane: scope
authorization, safe destination handling, durable events, provenance, scan
ownership, recovery, and explainable reporting. v2 dashboard/API work can be
presented as an extension only if it is implemented and evaluated before the
snapshot freeze.

Do not expand the research questions merely because the product gains more
adapters. Active scanning, distributed workers, PostgreSQL, authentication, or
AI prioritization should be included in the thesis only with their own
requirements, threat analysis, and evaluation evidence.

## Evidence freeze checklist

Before writing the final evaluation chapter, record:

1. Git commit or archive identifier.
2. Python version and dependency versions.
3. Operating system and hardware context.
4. Configuration files used for each experiment.
5. Complete deterministic test output.
6. Repeated SQLite/concurrency measurements.
7. Authorized live-scan identifiers and sanitized reports.
8. Known limitations and intentionally unimplemented features.
9. Screenshots and generated artifacts used in the thesis.
10. Database schema version and migration state.

## Timeline

### Now through the next development phase

- Build and verify the literature base.
- Keep the research questions stable.
- Continue v2 engineering in small, test-backed increments.
- Maintain a dated engineering log linking changes to evidence.

### Approximately 8-12 weeks before submission

- Freeze the thesis feature set and repository snapshot.
- Stop adding features that are not required for the research questions.
- Run the complete evaluation again from a clean environment.
- Export final tables, figures, reports, and test summaries.

### Final writing period

- Write the thesis against the frozen snapshot.
- Describe later repository work as post-freeze development, not as silently
  mixed evaluation evidence.
- Update the README and release notes separately from the academic snapshot.

This approach lets Sh4q progress toward v2 while keeping the 80+ page paper
reproducible, honest, and defensible.
