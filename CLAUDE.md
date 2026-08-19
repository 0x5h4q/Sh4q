# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Sh4q is a scope-aware, **discovery-only** reconnaissance orchestration framework. It resolves DNS, probes HTTP, and enumerates subdomains via Certificate Transparency logs, then records what it finds as a property graph. Everything is gated by an authorization ("scope") engine so the tool only ever touches assets it has been explicitly authorized to. Keep new plugins passive/discovery-only unless there is a deliberate reason not to (see `risk_level` below).

## Commands

```bash
pip install -e .                              # editable install; provides the `sh4q` console script (Python >=3.11)

sh4q scan example.com                         # scan with a default scope (target + its subdomains on 80/443)
sh4q scan example.com --config config/default.yaml
python -m sh4q scan example.com               # equivalent, via __main__.py

python tests/test_dns.py                      # run ONE test (see testing note below)
```

The CLI exits `0` if the target was in scope, `1` if scope denied it.

## Testing model (important — not pytest)

Files in `tests/` are **standalone executable scripts**, not a pytest suite:

- Each ends with `asyncio.run(main())` (or runs module-level code) and verifies behavior by **`print()` output that you read**, not `assert`. There are no pytest-collectable `test_*` functions and `pytest-asyncio` is not installed — running `pytest` collects zero tests while still executing scripts' side effects during import. **Run them individually: `python tests/test_<name>.py`.**
- Several make **real network calls** (`test_dns*`, `test_integration`, anything exercising the HTTP/CT plugins hits DNS, crt.sh, certspotter, and live HTTP) and write throwaway DBs to `/tmp/sh4q_*.db`. `test_scope_manual.py` and `test_storage_manual.py` are offline and deterministic.

## Architecture

The whole run is wired together in `sh4q/application/scan_runner.py:run_scan` — read that first. All components share **one SQLite file** at `<output.directory>/sh4q.db` (default `./sh4q-output/sh4q.db`): graph storage, evidence, and the event log are separate tables in it.

Pipeline: `config → ScopeEngine + storage + evidence + event log → EventBus (discovery handler subscribed) → recover replayed events → Scheduler runs plugins → each Discovery is published as a "discovery" Event → handler persists it → drain → ScanSummary`.

### Two-gate scope enforcement (the core invariant)

`ScopeEngine` (`sh4q/scope/engine.py`) is consulted at two distinct points:

- **Gate 1** — `Scheduler.run()` authorizes the *scan target* before any plugin executes. Denied → nothing runs.
- **Gate 2** — the discovery handler (`sh4q/handlers.py`) authorizes each *newly discovered asset* (resolved IP, HTTP host, subdomain) before persisting it as a graph node. Out-of-scope discoveries are dropped from the graph.

Note the ordering in the handler: **raw evidence is appended first, unconditionally**, then Gate 2 decides whether the asset also becomes a graph node/relationship. Evidence is the audit trail; the graph is the in-scope subset.

Scope matching supports CIDR/IP membership, exact hostname, and **subdomain inheritance** (`sub.example.com` is in scope if `example.com` is listed). The `excluded` list always wins. There is a single **request budget** counter shared across the whole run — *every* passing `authorize()` call (Gate 1 and every Gate 2 check) decrements it; once exhausted, all further authorizations DENY.

### Events: durability + at-least-once ⇒ handlers must be idempotent

`EventBus` (`sh4q/events/bus.py`) is an async queue with a background dispatcher. When given a `DurableEventLog`, each event is written `PENDING → PROCESSING → COMPLETED` in SQLite. On startup `bus.recover()` re-queues any non-`COMPLETED` event, so **delivery is at-least-once across crashes** — handlers can see the same event twice.

This is safe because persistence is idempotent by construction:
- Node id = `type:value`; relationship id = `from_id:type:to_id` (deterministic, in `storage/models.py`).
- `SQLiteStorage.save_node` uses `ON CONFLICT DO UPDATE` merging attributes via `json_patch`; relationships and evidence use `INSERT OR IGNORE`.
- Evidence PK is the `Event.id`, so replaying an event re-appends identical evidence as a no-op.

**When adding a handler or storage write, preserve idempotency** — assume every event may be delivered more than once.

### Plugins

`Plugin` ABC (`sh4q/plugins/interface.py`): async `preflight()` / `execute(target) -> list[Discovery]` / `cleanup()`, plus `PluginMetadata` (name, `dependencies`, `timeout`, `risk_level`, `required_scope`). A `Discovery` is just `{kind, data}`.

- **Registration is explicit** in `scan_runner.py` (`[DNSPlugin(), HTTPPlugin(), CTPlugin()]`). There is **no auto-discovery** despite the package name — `plugins/discovery.py` defines the `Discovery` dataclass, it is not a loader. Add a plugin by importing and adding it to that list.
- **Ordering** is a topological sort over `metadata.dependencies` (`Scheduler._ordered_plugins`); e.g. `http` depends on `dns`. A cycle or unmet dependency raises.
- **Retries are the Scheduler's job, not the plugin's.** A per-plugin `timeout` (via `asyncio.wait_for`) is retried with exponential backoff + jitter. Generic exceptions are **not** retried. A plugin signals a *transient, domain-specific* failure by returning a `Discovery` whose `data["retryable"] is True` (e.g. DNS `EAI_AGAIN`, HTTP 5xx) — the Scheduler then retries the whole `execute()`.
- `risk_level` (`passive`, `active-low`, …) and `required_scope` are **declarative metadata only** — not currently enforced anywhere.

### Single-pass, no recursion

The Scheduler runs the plugin chain **once** against the single CLI target. Discovered subdomains/IPs are persisted but are **not** fed back as new scan targets — there is no recursive expansion today. If you add crawling/expansion, that is a scheduler-level change and must respect the shared budget and Gate 2.

### Storage: a property graph over SQLite

`storage/` models a graph: `Node(type, value, attributes)` and `Relationship(from_id, to_id, type)`. Relationship types currently produced: `RESOLVES_TO` (domain→ip), `SERVES` (domain→url), `HAS_SUBDOMAIN` (domain→domain). `StorageRepository` is a `Protocol`; `SQLiteStorage` is the implementation.

### Config

Pydantic v2 models in `sh4q/config/schema.py`; `load_config` parses YAML. Sample configs live in repo-root `config/` and `sh4q/config/example_com.yaml`. Without `--config`, the scan builds a target-only scope on ports 80/443 (`_default_config`). All run output/state is confined to `output.directory`.
