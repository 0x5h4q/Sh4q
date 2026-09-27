# Releasing Sh4q

The process actually used for `v1.0.0` through `v1.2.0`, written down so it is
repeatable. Sh4q is a single-maintainer project with no working remote CI, so
every gate below is a local one. Do not describe any part of it as automated.

## Versioning

Semantic versioning, with a `v`-prefixed annotated tag (`v1.2.0`).

| Change | Bump |
| --- | --- |
| New operator-visible capability, new CLI flag, new stage | **minor** |
| Bug fix, documentation correction, packaging fix, no behaviour change | **patch** |
| Removing or renaming a flag, config key, or output field; changing an exit code; a schema the CLI can no longer read | **major** |

Two project-specific rules:

- **A scope, Gate 1, or Gate 2 fix is never "just a patch" in the notes.** It may
  be a patch by SemVer, but it is called out explicitly in the changelog, because
  the whole product claim is that those boundaries hold.
- **A database schema migration is at least a minor**, even when the CLI surface
  is unchanged. `CURRENT_SCHEMA_VERSION` in `sh4q/storage/db.py` moving means an
  older Sh4q can no longer open a newer database.

The single source of version truth is `version` in `pyproject.toml`. The tag, the
changelog heading, `docs/current_state.md`, and the README release badge and link
must all agree with it; `tests/test_documentation_qa.py` enforces several of
these and fails the release if they drift.

## Branch and pull-request flow

Every change reaches `main` through a pull request. No direct commits.

| Prefix | For |
| --- | --- |
| `feature/` | new capability |
| `fix/` | bug fix |
| `test/` | coverage with no behaviour change |
| `docs/` | documentation only |
| `chore/` | tooling, packaging, repository maintenance |
| `release/` | the release-preparation branch described below |

Merge with a merge commit, not a squash, and delete the branch afterwards. The
history is a record of what was proposed and reviewed, not only of what changed.

Pull request descriptions state motivation, implementation, the exact commands
run, and anything left unverified. `CONTRIBUTING.md` holds the full contract,
including the rule that changes broadening target contact or touching scope
enforcement need policy review **before** implementation.

## Before any merge

```bash
python tools/run_offline_tests.py
```

This is the suite. With remote CI unavailable it is the only gate, so it runs on
every branch before merge, including Dependabot branches. Add focused runs for
whatever the change touches, and `tests/test_documentation_qa.py` for anything
that edits documentation.

## Cutting a release

**1. Open a `release/X.Y.Z-readiness` branch.** One pull request carries the
whole release preparation:

- bump `version` in `pyproject.toml`;
- add the `CHANGELOG.md` entry, newest first, as `## X.Y.Z - YYYY-MM-DD`: a
  one-line characterisation of the release, then bullets in operator-visible
  terms. Say what an operator can now do, not which function changed;
- update `docs/current_state.md`: published release, package version, feature
  status, and the development-order list;
- update `README.md`: release badge, release link, pinned `pipx` install line,
  and any capability text that is now wrong;
- update `docs/v1_roadmap.md` so completed milestone items move out of the
  pending list.

**2. Run the acceptance checklist** from a clean checkout of the merged `main`:

```bash
git switch main
git pull --ff-only origin main
python -m pip install -e .
sh4q --version                                    # agrees with pyproject.toml
sh4q --help
sh4q scan --help
PYTHONPATH=. python tests/test_documentation_qa.py
PYTHONPATH=. python tests/test_config_schema_version.py
python tools/run_offline_tests.py                 # must be fully green
git status --short                                # nothing staged, nothing stray
```

Acceptance means: version and documentation agree, CLI help opens without a
traceback, the offline suite passes in full, network-dependent checks are
identified and run only against authorised targets, and no database, report,
recording, candidate list, or target evidence is present in the tree.

**3. Build and verify the artefacts.**

```bash
python -m build
python -m pip install --force-reinstall dist/sh4q-X.Y.Z-py3-none-any.whl
sh4q --version
sh4q doctor
python -c "import importlib.resources as r; print(r.files('sh4q').joinpath('assets/banner.png').is_file())"
```

Install the built wheel into a **fresh** environment, not the development one.
The banner check is not superstition: package data has been dropped from a wheel
before (see `0.1.0-alpha.52`), and a source checkout will not reveal it.

**4. Tag and publish.**

```bash
git tag -a vX.Y.Z -m "Sh4q vX.Y.Z"
git push origin vX.Y.Z
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file <release notes> \
  dist/sh4q-X.Y.Z-py3-none-any.whl dist/sh4q-X.Y.Z.tar.gz
```

Annotated tags only. The release notes are the changelog entry, expanded with
anything an operator must know before upgrading.

**5. Follow up.** A `docs/post-release-X.Y.Z` branch reconciles anything the
release revealed. Releases have needed this every time; expect it.

## While GitHub Actions is unavailable

The account is billing-locked, so no workflow job can start. `Offline tests` and
`Release` are disabled manually and `release.yml` **has never run**. Every
release so far was built and verified by hand on one machine.

That is acceptable for this project, but state it plainly: never write that a
release was "CI verified". Record the machine, the Python version, and the suite
result in the release notes instead.

When the lock clears: `gh workflow enable` for both workflows, restore
`open-pull-requests-limit: 5` for the `github-actions` Dependabot ecosystem,
require `offline-tests` in branch protection, and verify `release.yml` against a
throwaway pre-release tag **before** trusting it with a real one.

## Hotfixes

For a release-blocking defect — a scope or Gate bypass, data loss, or a CLI that
will not start:

1. Branch `fix/<behaviour>` from `main`.
2. Write the failing test first, so the defect cannot return silently.
3. Fix, then run the full offline suite.
4. Merge, bump the patch version, and release using the steps above. A hotfix
   skips no step of the acceptance checklist; it only skips the wait.

## Rollback

A published tag and release are never rewritten or deleted — they are what other
people installed. Roll forward with a new patch version instead.

If a release must be withdrawn, mark the GitHub release as a pre-release, state
the reason in its notes, point readers at the last good version, and ship the
replacement. Note that `pip install sh4q==X.Y.Z` against a git tag keeps working
regardless, which is another reason the replacement matters more than the label.
