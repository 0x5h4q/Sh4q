# Repository Guidelines

## Project Structure & Module Organization

`sh4q/` contains the Python package. The CLI entry point is `sh4q/cli/main.py`, while `sh4q/application/scan_runner.py` wires together scans. Core areas are separated into `scope/`, `storage/`, `events/`, and `plugins/`; shared orchestration lives in `scheduler.py` and `handlers.py`. Configuration models and examples are under `sh4q/config/`, with repository-level defaults in `config/`. Standalone checks live in `tests/`. Runtime SQLite data is written to `sh4q-output/` by default and should not be committed.

## Build, Test, and Development Commands

- `python -m venv venv && source venv/bin/activate` creates and activates a local environment.
- `pip install -e .` installs the package in editable mode and provides the `sh4q` command.
- `sh4q scan example.com` runs a scan using target-derived default scope.
- `sh4q scan example.com --config config/default.yaml` runs with explicit YAML configuration.
- `python tests/test_scope_manual.py` runs an offline, deterministic check.
- `python tests/test_integration.py` exercises integrated behavior and may make real network requests.

The files in `tests/` are executable scripts, not pytest-collectable tests. Run each relevant file directly and inspect its printed results.

## Coding Style & Naming Conventions

Use four-space indentation, standard PEP 8 layout, and type hints for public interfaces. Name modules, functions, and variables with `snake_case`; classes use `PascalCase`; constants use `UPPER_SNAKE_CASE`. Keep async boundaries explicit with `async`/`await`. Prefer small components aligned with existing package boundaries. No formatter or linter is configured in `pyproject.toml`, so keep imports grouped and changes consistent with nearby code.

## Testing Guidelines

Add focused scripts named `tests/test_<behavior>.py`. Preserve the current script-style convention using `asyncio.run(main())` where needed. Favor offline fakes for scheduler, scope, storage, and event behavior. Clearly identify checks that contact DNS, HTTP endpoints, or certificate-transparency services. Use unique `/tmp/sh4q_*.db` paths and clean stale files before each run.

## Commit & Pull Request Guidelines

History mixes concise imperatives (`Fix scan pipeline...`, `Add ScopeStatus...`) with informal messages. Use the clearer pattern: start with an imperative verb, name the affected behavior, and keep the subject focused. Pull requests should explain the motivation, summarize implementation changes, list commands executed, and note network-dependent tests. Link related issues and include CLI output when user-visible behavior changes; screenshots are generally unnecessary for this command-line project.

## Architecture & Safety Notes

Scope enforcement is a core invariant: validate plugin targets and newly discovered assets before persistence. Event delivery is at-least-once, so handlers must remain idempotent. Never commit scan databases, captured evidence, credentials, or sensitive target data.
