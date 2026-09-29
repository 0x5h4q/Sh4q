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
