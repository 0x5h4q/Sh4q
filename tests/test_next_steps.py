"""A scan says what is worth running against what it just found.

The default scan on a real target recorded 907 hostnames and verified
none of them, and said nothing about it. The command that would have
checked them existed; the operator had no reason to know. Suggesting it
where the gap appears is more use than documenting it somewhere else.
"""

from types import SimpleNamespace

from sh4q.cli.main import next_steps


def summary(**overrides) -> SimpleNamespace:
    base = dict(
        target="example.com",
        database_path="./sh4q-output/sh4q.db",
        ct_names=0,
        adapter_names=0,
        http_endpoints=0,
        discoveries=0,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def joined(steps) -> str:
    return "\n".join(steps)


# --- names found but never checked: the case that motivated this ----------
unchecked = joined(next_steps(summary(ct_names=907, discoveries=908, http_endpoints=1),
                              resolved_stage_ran=False))
assert "907 hostname(s) were found but not checked" in unchecked, unchecked
assert "sh4q scan example.com --resolve" in unchecked, unchecked

# Once they have been checked, the suggestion must not persist.
checked = joined(next_steps(summary(ct_names=907, discoveries=908, http_endpoints=1),
                            resolved_stage_ran=True))
assert "not checked" not in checked, checked
assert "--resolve" not in checked, "a completed action must not be suggested again"
assert "--names" in checked, "the composition view is still worth offering"

# --- suggestions follow what the scan actually produced -------------------
empty = next_steps(summary(), resolved_stage_ran=True)
assert empty == [], f"a scan that found nothing has nothing to suggest: {empty}"

no_endpoints = joined(next_steps(summary(ct_names=5, discoveries=5), resolved_stage_ran=True))
assert "--response-attributes" not in no_endpoints, (
    "response attributes are pointless with no endpoint"
)
assert "--names" in no_endpoints

no_names = joined(next_steps(summary(http_endpoints=2, discoveries=2), resolved_stage_ran=True))
assert "--names" not in no_names, "nothing to summarise without hostnames"
assert "--response-attributes" in no_names

# Adapter names count towards the same suggestion as CT names.
adapter_only = joined(next_steps(summary(adapter_names=12, discoveries=12), resolved_stage_ran=False))
assert "12 hostname(s)" in adapter_only, adapter_only

# --- the commands are usable as printed -----------------------------------
# The default database needs no flag; a custom one must carry it, or the
# suggested command would read the wrong database.
default = joined(next_steps(summary(ct_names=1, discoveries=1), resolved_stage_ran=True))
assert "--database" not in default, "the default path should not be repeated"

custom = joined(next_steps(
    summary(ct_names=1, discoveries=1, database_path="./engagements/a/sh4q.db"),
    resolved_stage_ran=True,
))
assert "--database ./engagements/a/sh4q.db" in custom, custom

for line in custom.splitlines():
    stripped = line.strip()
    if stripped.startswith("sh4q "):
        assert "--latest" in stripped and "--target example.com" in stripped, stripped

# The scope selector the run used must survive into a suggested re-scan.
# Without it, following the advice after a `--config` run silently falls back
# to a target-only scope on ports 80/443; against the localhost lab scope it
# refused every address it had just resolved, because
# `allow_private_addresses` is off by default. The operator had done nothing
# wrong -- the tool told them to do the wrong thing.
scoped = joined(next_steps(
    summary(ct_names=16, discoveries=18, database_path="./local/lab/out/sh4q.db"),
    resolved_stage_ran=False,
    scope_flags="--config local/lab/scope.yaml ",
))
assert "sh4q scan example.com --config local/lab/scope.yaml --resolve" in scoped, scoped

# No config was passed, so none may be invented.
unscoped = joined(next_steps(summary(ct_names=16, discoveries=18), resolved_stage_ran=False))
assert "sh4q scan example.com --resolve" in unscoped, unscoped
assert "--config" not in unscoped, unscoped

# A template owns stage selection, so the parser refuses `--template X
# --resolve`. Suggesting it would print a command that cannot run.
templated = joined(next_steps(
    summary(ct_names=16, discoveries=18),
    resolved_stage_ran=False,
    scope_flags="--config resolved.yaml ",
    template="local/lab/template.yaml",
))
assert "local/lab/template.yaml" in templated, templated
assert "--resolve" not in templated, (
    f"a template run must not be told to pass --resolve: {templated}"
)

# The scope selector must not leak into the read-only views: they read the
# database, and `sh4q results --config ...` is not a valid command.
views = next_steps(
    summary(ct_names=16, http_endpoints=2, discoveries=18,
            database_path="./local/lab/out/sh4q.db"),
    resolved_stage_ran=True,
    scope_flags="--config local/lab/scope.yaml ",
)
assert views, "a scan with names and endpoints must suggest something"
for step in views:
    assert "--config" not in step, f"a read-only view needs no scope: {step}"
    assert "--database ./local/lab/out/sh4q.db" in step, step


print("next steps test passed")


# --- the unchecked count means two different things ------------------------
# A real scan resolved names up to its bound and still reported 407 as "not
# checked (run with --resolve)" to an operator who had just run resolution.
from sh4q.application.results import NameComposition  # noqa: E402

nothing_tried = NameComposition(
    total=907, resolved=0, unresolved=0, unchecked=907,
    auto_issued=0, auto_issued_resolved=0, label_counts=(),
)
assert nothing_tried.resolved == 0 and nothing_tried.unresolved == 0, (
    "with nothing attempted, suggesting --resolve is the correct advice"
)

bound_limited = NameComposition(
    total=907, resolved=171, unresolved=329, unchecked=407,
    auto_issued=524, auto_issued_resolved=0, label_counts=(("www", 133),),
)
assert bound_limited.resolved + bound_limited.unresolved > 0, (
    "resolution ran, so the remainder is past the bound and --resolve is "
    "advice the operator has already taken"
)
assert bound_limited.resolved + bound_limited.unresolved + bound_limited.unchecked == bound_limited.total


# --- a recovered run explains its own arithmetic ---------------------------
# A scan that replayed 207 events from an interrupted predecessor reported
# 5488 stored evidence against 2651 from this scan, which reads as a counting
# error unless the replay is stated.
import contextlib  # noqa: E402
import io  # noqa: E402

from sh4q.cli.main import render_summary  # noqa: E402


def rendered(**overrides) -> str:
    base = dict(
        target="example.com", scan_run_id="a" * 32, scope_allowed=True, scope_reason="ok",
        recovered_events=0, discoveries=1, dns_addresses=1, http_endpoints=0, ct_names=0,
        adapter_names=0, resolved_discovered_addresses=0, resolved_discovered_attempted=0,
        resolved_discovered_failures=0, technologies=0, dns_failure_reasons={}, relationships=1,
        evidence=1, evidence_this_scan=1, duration_seconds=1.0,
        database_path="./sh4q-output/sh4q.db", requests_admitted=1, requests_denied=0,
        requests_completed=1, requests_failed=0, peak_request_concurrency=1, stage_durations={},
        historical_urls=0, historical_urls_rejected=0, historical_urls_truncated=0,
    )
    base.update(overrides)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        render_summary(SimpleNamespace(**base), resolved_stage_ran=True)
    return out.getvalue()


recovered = rendered(recovered_events=207, evidence=5488, evidence_this_scan=2651)
assert "recovered 207 event(s)" in recovered
assert "previous interrupted scan was replayed" in recovered, (
    "the count difference must be explained where it appears"
)

# A clean run says nothing about recovery.
clean = rendered()
assert "recovered" not in clean and "replayed" not in clean, clean
