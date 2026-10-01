# sh4q Scope & Architecture Review

- **Repository state:** `main` @ `55563d4`, package v1.3.0 (disposable working copy; inspected read-only)
- **Date:** 2026-10-01
- **Method:** live code at `sh4q/` only (the `build/lib/` tree is a stale duplicate and was ignored). All claims were traced to specific lines. Where a claim needed proof, it was verified with in-memory probes against the real `ScopeEngine`/handler code (no files created, no network, no scans). The repo's own offline suite was run once via `venv/bin/python tools/run_offline_tests.py`: **90/90 pass**, 6 network tests skipped — consistent with `docs/current_state.md` ("90 offline tests").

---

## Contents

1. [Architecture summary](#1-architecture-summary)
2. [Scope-flow diagram](#2-scope-flow-diagram-plain-text)
3. [Gate 1 analysis](#3-gate-1-analysis)
4. [Gate 2 analysis](#4-gate-2-analysis)
5. [Documentation vs code](#5-documentation-vs-code)
6. [Potential inconsistencies / bugs](#6-potential-inconsistencies--bugs)
7. [Test coverage gaps](#7-test-coverage-gaps)
8. [Recommended fixes](#8-recommended-fixes-not-implemented)

---

## 1. Architecture summary

**Layering (outside-in):** `sh4q/cli/main.py` parses flags/profiles/templates and calls
`application/scan_runner.py::run_scan` (sh4q/cli/main.py:733, 747). `run_scan` builds config
(`config/loader.py` → pydantic `schema.py`), instantiates `ScopeEngine`, storage, evidence,
durable event log, scan-asset store, and the plugin list, then hands everything to `Scheduler`
(sh4q/application/scan_runner.py:175-239, 423-429).

**Core invariant chain:**

- **`scope/engine.py`** — the only policy authority:
  - `authorize(host, port)` (engine.py:40-54)
  - `authorize_resolved_address(ip)` (engine.py:56-74)
  - `normalize_target` (engine.py:99-112)
  - Matching is exact / `endswith("." + pattern)` subdomain inheritance / CIDR membership
    (engine.py:79-97), with **exclusion checked before** target-list match (engine.py:43-44).
- **`scheduler.py`** — Gate 1 (scheduler.py:286-295), dependency-ordered stage execution
  (`_ordered_plugins`, scheduler.py:55-84), per-stage retry/timeout bookkeeping, then the
  `accept_discoveries` hand-off **before** event publish (scheduler.py:357-360), and durable
  event publication + drain (scheduler.py:362-378).
- **`handlers.py`** — one function per discovery kind, registered in `_BY_KIND`
  (handlers.py:601-632). Every event is appended to evidence **before** Gate 2
  (handlers.py:641-650) — denials are auditable; the graph only ever receives the authorized
  subset. Node id is `type:value`, relationship id `from:type:to` (storage/models.py:20-22,
  33-35) with upsert/`INSERT OR IGNORE` semantics, so at-least-once redelivery is idempotent
  (storage/sqlite_storage.py:56-111).
- **`network/http.py`** — `ScopedHTTPClient` is the request-time gate:
  `_authorize_url` re-authorizes host+port, resolves, and denies if *any* resolved address
  fails `authorize_resolved_address`, then the request is pinned to the approved IP while
  preserving SNI/Host (`_PinnedIPTransport`, http.py:24-62). Redirects loop with per-hop
  re-authorization (http.py:106-131, 147-176). `TrustedServiceHTTPClient` (http.py:255-311)
  covers CT providers: HTTPS/443 only, host allow-list, redirects denied, global-IP required.
- **`plugins/`** — native stages (dns, http, ct, discovered-dns, discovered-http, vhost,
  directory, JS extraction/bundles) plus `ExternalAdapterPlugin` wrapping external tools via
  `ControlledProcessRunner` (adapters/runner.py: argv-only, executable allow-list, output
  ceiling, no shell).
- **`adapters/`** — subfinder/katana/waybackurls/httpx parsers whose output is treated as
  untrusted `Discovery`s; every emitted kind is re-gated at the handler.

**Stage assembly & order** (scan_runner.py:239-422): default `dns → http → ct`.
`--sub` appends subfinder; `--resolve` / `--hosts-file` / `--sub` append discovered-dns +
discovered-http (scan_runner.py:325-336); `--js` appends JS extraction (+ bundles), whose
dependency makes it follow discovered-http when enrichment is on
(javascript_extraction_plugin.py:27); `--httpx` appends the httpx fingerprint stage;
vhost/directory sweep a single origin chosen by `primary_probe_target`
(network/probes.py:55-67). The default order matches the doc claim
"dns → http → certificate transparency" (docs/current_state.md:50-54). ✅

---

## 2. Scope-flow diagram (plain text)

```
 operator CLI (target, config/template, stage flags)
        |
        v
 +------------------+
 | GATE 1           |  scheduler.run -> scope.authorize(target)      scheduler.py:286
 | hostname only    |  deny => return decision, exit 1 (cli/main.py:797)
 +------------------+
        | allow
        v
 Scheduler: plugins in dependency order (_ordered_plugins)             scheduler.py:306
   for each stage:
     preflight -> execute (retry/timeout bounded)                      scheduler.py:141-279
     |         <--- plugin contacts network ONLY via ScopedHTTPClient --+
     |                  _authorize_url: authorize(host,port)            network/http.py:228-246
     |                  resolve -> authorize_resolved_address(all IPs)  (deny if ANY bad)
     |                  pin IP, per-redirect-hop re-authorization       network/http.py:106-131
     v
 accept_discoveries(discoveries, source) on ALL plugins              scheduler.py:357-360
   (discovered-dns admits ct/subfinder names; discovered-http admits
    discovered-dns resolutions; httpx admits http probes) -- each re-authorizes
        |
        v
 bus.publish(discovery event) -> durable event log (PENDING)         scheduler.py:362-374
        |
        v
 +------------------+
 | GATE 2           |  handle_discovery: evidence FIRST, then kind handler  handlers.py:634-658
 | per-observation  |  authorize(hostname[,port]) and/or authorize_resolved_address(ip)
 +------------------+
   deny  => gate_line printed, nothing persisted (evidence keeps it)   e.g. handlers.py:94-99
   allow => Node/Relationship upserts + scan_assets.record             handlers.py:41-64
        |
        v
 graph (nodes/relationships) -> results/export/diff views
        ...
 interrupted scans: DurableEventLog keeps PENDING/PROCESSING/FAILED;
 next scan: bus.recover() re-queues them BEFORE Gate 1 of that scan    scan_runner.py:221, event_log.py:139-150
```

**Downstream movement of discovered assets:**

- CT/subfinder `subdomain_found` → `DiscoveredDNSPlugin.accept_discoveries`
  (only `SUBDOMAIN_SOURCES = {ct, subfinder}`, discovered_dns_plugin.py:19, 171-183)
  → admission re-authorized (`_admit`, discovered_dns_plugin.py:126-134)
  → `discovered_dns_resolution` events → handler authorizes hostname **and** IP
  (handlers.py:94-104)
  → `DiscoveredHTTPPlugin.accept_discoveries` re-authorizes (discovered_http_plugin.py:45-62)
  → probes reuse `HTTPPlugin` with `ScopedHTTPClient`.
- `--hosts-file` names enter through the same `_admit` path via the constructor
  (`names=supplied_hosts`, scan_runner.py:326-329).
- JS extraction reads this scan's `http_probe` evidence for HTML samples
  (scan_runner.py:338-341); bundle fetches authorize host+port then go through
  `ScopedHTTPClient` (scan_runner.py:344-370).
- httpx receives only scan-owned, re-authorized probe URLs (httpx_plugin.py:23-32).

---

## 3. Gate 1 analysis

Gate 1 is exactly one call: `scope.authorize(target)` with no port (scheduler.py:286).

- **Subdomain inheritance is by design**: `example.com` authorizes any depth of subdomain
  (engine.py:94-95; tested test_scope_engine.py:56-57). Sibling/parent tricks are rejected at
  the dot boundary (`notexample.com`, `example.com.evil.com` — tested, test_scope_engine.py:60-61).
- **Exclusions win** over allow-list matches and inherit downward (engine.py:43-44; tested
  lines 66-72).
- **Normalization before comparison**: NFKC, trailing-dot strip, IDNA+casefold for names,
  canonical form for IPs (engine.py:99-112). Verified: `"ｅxample.com"` folds onto
  `example.com` (allow), Cyrillic homoglyphs do not (deny), punycode/Unicode forms are
  equivalent (test_scope_engine.py:107-119).
- **Fail-closed verified**: `""` → DENY; `"example.com:8080"` → DENY (port-in-string is not
  stripped, so it matches nothing); `"010.0.0.5"`-style leading-zero IP text is rejected by
  `ipaddress` (test_scope_engine.py:121-125).
- **What Gate 1 does *not* do**: no address-safety check on the target's IP. That is deferred
  to Gate 2 by design — the `dns` stage resolves the Gate-1-authorized target and the handler
  applies `authorize_resolved_address` (handlers.py:75), and every later HTTP contact
  re-checks at request time (network/http.py:233, 243). There is no TOCTOU window because
  connections are pinned to the policy-approved IP (http.py:37-62).
- **Port semantics**: Gate 1 passes `port=None`, so the port rule (engine.py:51-52) never
  applies to the initial target; ports gate contacts per-origin later. An empty `ports` list
  authorizes *any* port (engine.py:51) while probing stays bounded to 80/443 (probes.py:34, 47)
  — both documented (limitations.md:71-79). ✅ code matches docs.

Nuance: a denied scan still records a scan run marked `COMPLETED` with zero assets and exits 1
(scan_runner.py:465, cli/main.py:797) — cosmetic; arguably should be a distinct outcome.

---

## 4. Gate 2 analysis

Gate 2 lives in two places, and the redundancy is deliberate.

**Request-time (contact):** `ScopedHTTPClient._authorize_url` — scheme/host sanity,
`authorize(host, port)` with the *effective* port, resolution,
`authorize_resolved_address` over **every** answer, deny-on-any-bad (mixed public/private
answers rejected; test_scoped_http.py:52-62), then IP pinning (network/http.py:228-246).
Redirects re-run the whole check per hop (http.py:106-131); redirect-limit raises
`ScopedHTTPError`. Vhost/directory probes use `follow_redirects=False` plus their own
plugin-side `authorize(candidate, port)` (vhost_discovery_plugin.py:126,
directory_discovery.py:125). The JS bundle fetcher port-checks before fetching
(scan_runner.py:347). This layer is tight; no contact-path bypass was found.

**Persistence-time (inventory):** per-kind handlers authorize before saving:

| Kind | Handler check | Location |
| --- | --- | --- |
| `discovered_dns_resolution` | hostname **and** resolved address | handlers.py:94-104 |
| `http_probe` | host of canonical final URL | handlers.py:130-135 |
| `subdomain_found` | parent **and** child (parent first — fixed regression) | handlers.py:517-529; test_scope_engine.py:192-197 |
| `url_history_batch` / `url_history_found` | host only | handlers.py:181, 229 |
| `javascript_*` | host only | handlers.py:299 |
| `http_fingerprint` | host only | handlers.py:328 |
| `vhost_observation` | candidate only (no port) | handlers.py:383 |
| `directory_observation` | host **and** port | handlers.py:458-463 |

Evidence is written for everything, including denials (handlers.py:641-650; asserted in
test_scope_engine.py:188-190). The asymmetries in the table are item B-2 below.

---

## 5. Documentation vs code

- `BACKLOG.md:14` header snapshot says "85/85 pass / 92 test files" — **stale**; the suite is
  90/90 (matches docs/current_state.md:237, as expected).
- `docs/current_state.md` stage order, template/profile behavior, `--vhosts-from-scan` /
  `--vhosts-file` pairing, and "every authorized port probed" all match code.
- `docs/threat_model.md` controls list matches code, with one over-broad line:
  "Gate 2 validates discovered hostnames … before trusted persistence" — true for every kind
  **except** `dns_resolution`, whose hostname is never re-validated (item B-1 below).
- `docs/limitations.md` port / single-origin-sweep statements match `probes.py` and the
  vhost/directory plugins exactly.
- `docs/threat_model.md:66` "httpx input is restricted to scan-owned, reauthorized endpoints"
  — matches `HttpxFingerprintPlugin._authorized` (httpx_plugin.py:29-32), noting it authorizes
  hostname only (the port came from already-port-authorized probe URLs, so it holds in practice).

---

## 6. Potential inconsistencies / bugs

### Confirmed (code path; B-1 and B-2 also demonstrated live)

**B-1 — `dns_resolution` handler never authorizes the hostname.**
`_dns_resolution` (handlers.py:66-87) saves the domain node *unconditionally* and applies only
`authorize_resolved_address(ip)`. The comment (handlers.py:73-74) says "The hostname was
authorized at Gate 1" — true only while `dns` is the sole emitter and the event belongs to the
current scan. The durable event log breaks that assumption: `run_scan` recovers unfinished
events from **all** previous scans sharing the DB (scan_runner.py:221; event_log.py:143
recovers `PENDING/PROCESSING/FAILED` of any target), and re-dispatched events are handled by
the *current* scan's scope. A recovered `dns_resolution` from a scan of a different target
persists the out-of-scope domain, its IP, and a `RESOLVES_TO` edge.

*Demonstrated in memory:* with scope `targets=[example.com]`, a `dns_resolution` event for
`evil.com` produced `domain:evil.com`, `ip:93.184.216.34`, and the edge — while the equivalent
`subdomain_found` event was correctly denied.

*Impact:* contact-safety none (no request is made); graph integrity real. It is the one kind
where the threat-model claim does not hold.

**B-2 — Persistence-side port policy is inconsistent across handlers.**
`_directory_observation` authorizes `authorize(host, port)` (handlers.py:458-463) and the
plugins port-check (vhost_discovery_plugin.py:126, directory_discovery.py:125,
scan_runner.py:347), but `_http_probe` (handlers.py:132), `_url_history_batch`
(handlers.py:181), `_url_history_found` (handlers.py:229), `_javascript_reference`
(handlers.py:299), `_http_fingerprint` (handlers.py:328), and `_vhost_observation`
(handlers.py:383) authorize host only. For `http_probe` this is harmless — request-time
enforcement guarantees the final URL's port was authorized. For the persist-only kinds it
means, e.g., `https://example.com:8443/` in waybackurls output becomes inventory while 8443 is
not in `scope.ports`.

*Demonstrated for the vhost handler:* a `vhost_observation` event on port 8443 persisted a URL
node with no port check (live scans are protected by the plugin, so this matters on recovery or
future emitters).

*Impact:* whether this is a bug or an undocumented design choice (ports gate *contact*, not
*inventory*) is undefined — today the codebase half-asserts both positions.

**B-3 — Confirmed fail-closed oddities in matching (behavior, not exploit).**
`authorize(".example.com")` → ALLOW (leading dot satisfies `endswith(".example.com")`) and
`authorize("*.example.com")` → ALLOW (CT providers emit wildcard names; fed straight through
ct_plugin.py:143-161). Both become literal domain nodes, and `DiscoveredDNSPlugin` will attempt
to resolve `*.example.com` (which can actually resolve via wildcard records). No contact or
integrity risk; inventory noise and an undocumented corner of the matching rule.

### Suspected (plausible from code; a test would prove/disprove)

**S-1 — `http` stage drops everything on timeout while sibling stages keep partials.**
On `timeout_exhausted`, `_execute_plugin` returns `[]` (scheduler.py:195-207), discarding any
probe results — but discovered-http, directory, and vhost deliberately return partials on
cancellation (discovered_http_plugin.py:80-102, directory_discovery.py:154-172,
vhost_discovery_plugin.py:136-142). With the default 2-probe stage the loss is small, but the
inconsistency looks unintended rather than principled.

**S-2 — IDNA fallback asymmetry in `normalize_target`.**
Names whose `encode("idna")` fails fall back to raw `casefold()` (engine.py:109-111). A
candidate that fails encoding (certain underscore/unicode mixes) is compared as text while an
equivalent encodeable target was punycoded — the two forms can never match: a silent false
negative. test_scope_engine.py only covers encodeable names.

**S-3 — CT `retryable` marks can re-run a rate-limited provider stage.**
`ct_provider_status` carries `retryable: error.retryable` (ct_plugin.py:135), and
`_retryable_discovery` triggers whole-stage retries (scheduler.py:86-106, 250-277). If a
connector's rate-limit error sets `retryable=True`, the stage re-runs against a provider that
just said "slow down", up to `max_retries`. Bounded, but wasteful; needs a fixture to confirm
the connector flags.

**S-4 — `_directory_observation` anchors to a synthetic `https://<target>/` root** regardless
of the scheme actually swept (handlers.py:482). When `scope.ports=[80]`, the relationship
claims a root URL that was never contacted. Inventory-accuracy nit.

### Checked and *not* bugs (negative results worth recording)

- **IPv4-mapped IPv6 loopback/private** (`::ffff:127.0.0.1`, `::ffff:10.0.0.1`) → correctly
  DENY on Python 3.14's `ipaddress`; `::ffff:8.8.8.8` → ALLOW. No bypass.
- **Zone-id link-local** (`fe80::1%eth0`) → DENY. Fullwidth-digit IP text folds under NFKC but
  then fails the address policy → DENY.
- **httpx URL `host`** strips brackets (`"http://[::1]:8080/"` → `"::1"`), so handler-level
  `authorize(host)` agrees with the engine for IPv6 literal targets — no false negative.
- **Port-embedded hostnames** (`"example.com:8080"` as a *target string*) → DENY everywhere
  (fail-closed), and adapters strip ports before emitting hostnames
  (discovered_dns_plugin.py:41-49, subfinder.py:27).
- **Mixed public/private DNS answers** deny the whole host (network/http.py:242-245,
  test_scoped_http.py:52-62) — a deliberate conservative false-negative; document rather
  than change.
- **`_url_history_batch` stats alignment** (`zip(accepted_nodes[1::2], …)`, handlers.py:211)
  is correct because nodes alternate domain/url by construction.
- **Recovery double-processing** is idempotent (node/relationship upserts,
  tests/test_idempotency.py) — but only under a *same-scope* replay (see gaps).

---

## 7. Test coverage gaps

Existing coverage is genuinely strong for the engine core: exclusion precedence, CIDR,
IDNA/homoglyphs, port list semantics, fail-closed parsing, parent-before-child gating in
`subdomain_found`, evidence-on-deny, redirect re-authorization, mixed-answer denial, and
bounded body reads (test_scope_engine.py, test_scoped_http.py). Gaps:

1. **Cross-scope event recovery** — no test replays recovered/unfinished events under a scope
   different from the one that produced them (test_idempotency.py:77, test_event_retry.py all
   replay same-scope). This is exactly the B-1 trigger.
2. **Port-aware persistence** — no test asserts what happens when a persisted URL
   (`url_history`, `javascript_reference`, `http_fingerprint`, `vhost_observation`) carries a
   port outside `scope.ports`; test_url_history_pipeline.py has no port case, and no test pins
   the intended answer.
3. **Engine matching corners** — no tests for port-embedded target strings, leading-dot names,
   `*.` wildcard names, IPv4-mapped IPv6 (behavior differs across Python versions — worth
   pinning), zone-id addresses, or IDNA-unencodable candidates (S-2).
4. **HTTP-stage timeout loss** (S-1) — test_stage_deadline_loss.py covers discovered-http /
   directory partials; the plain `http` stage's `[]`-on-timeout path isn't pinned.
5. **`--vhosts-from-scan` against a differently-scoped prior run** — candidates are
   re-authorized at execute (vhost_discovery_plugin.py:126) so it should hold, but nothing
   asserts it.
6. **CT retry interaction** (S-3) — no fixture where a connector returns `retryable=True` on a
   rate-limit error.

---

## 8. Recommended fixes (not implemented)

1. **Close B-1 (highest value, one line of policy):** in `_dns_resolution`, call
   `scope.authorize(domain)` before saving anything and move the domain-node save behind the
   checks. This makes the handler safe against recovered events and any future emitter, and
   brings the threat-model sentence back to universally true.
2. **Settle the persistence port policy (B-2):** either add
   `port = HttpURL(url).port or default` + `scope.authorize(host, port)` to the five host-only
   handlers, or document that ports gate contact only and drop the port check from
   `_directory_observation` so the rule is stated once. Recommendation: check ports at
   persistence too — it is cheap and makes "inventory ⊆ authorized" a stated invariant.
3. **Add the recovery regression test** from gap 1: build an event log under scope A with an
   unfinished `dns_resolution`, run a handler under scope B, assert nothing entered B's graph
   (and evidence still recorded it).
4. **Pin the matching corners** from gap 3 as assertions, especially IPv4-mapped IPv6 and
   port-in-string fail-closed behavior, so a Python/`ipaddress` upgrade cannot silently change
   the perimeter.
5. **Decide S-1 deliberately:** return partial discoveries from the plain `http` stage on
   timeout (like discovered-http), or document why a two-probe stage loses them.
6. **Tag or drop wildcard names** (`*.example.com`) at admission in `DiscoveredDNSPlugin` /
   inventory, or document that they may resolve.
7. **Docs:** refresh BACKLOG.md's stale header snapshot (85 → 90 tests, current head) and
   soften the threat-model Gate 2 sentence until fix 1 lands.
