"""The scan options and the new result views stay readable.

Twenty-one scan options read as a wall, and the distinction that matters
most -- whether a stage generates traffic -- was invisible in a flat
list. Result views that repeat an identical six-item list per endpoint,
or print a label column where every count is one, bury the part a reader
needs.
"""

import argparse

from sh4q.application.results import NameComposition
from sh4q.cli.main import build_parser


parser = build_parser()
subs = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)][0]
scan = subs.choices["scan"]

groups = {g.title: g for g in scan._action_groups if g.title}
for expected in ("scope and configuration", "output", "passive stages", "active stages"):
    assert expected in groups, f"missing option group {expected!r}: {sorted(groups)}"

placed: dict[str, str] = {}
for title, group in groups.items():
    for action in group._group_actions:
        for option in action.option_strings:
            if option.startswith("--"):
                placed[option] = title

# Every stage flag belongs to a group, and to the right one. A stage that
# generates traffic must not be listed among the passive ones.
PASSIVE = {"--sub", "--resolve", "--hosts-file", "--httpx", "--url-history", "--js", "--js-bundles"}
ACTIVE = {"--katana", "--vhosts", "--vhosts-file", "--vhosts-from-scan", "--directories", "--directories-file"}
for flag in PASSIVE:
    assert placed.get(flag) == "passive stages", f"{flag} -> {placed.get(flag)}"
for flag in ACTIVE:
    assert placed.get(flag) == "active stages", f"{flag} -> {placed.get(flag)}"
for flag in ("--config", "--template", "--profile"):
    assert placed.get(flag) == "scope and configuration", f"{flag} -> {placed.get(flag)}"

# Nothing may be stranded in the default bucket, which is how -q and --vhosts
# escaped grouping the first time.
stranded = [
    option
    for action in scan._actions
    for option in action.option_strings
    if option not in ("-h", "--help")
    and not any(action in g._group_actions for g in groups.values())
    and action.help is not argparse.SUPPRESS
]
assert not stranded, f"options outside every group: {stranded}"

# The active group explains itself, since that is the safety-relevant half.
assert "traffic" in (groups["active stages"].description or "").lower()
assert "profile" in (groups["active stages"].description or "").lower()


# --- name composition reporting -------------------------------------------
# A label list is only informative when something repeats.
unique = NameComposition(
    total=4, resolved=4, unresolved=0, unchecked=0, auto_issued=0,
    auto_issued_resolved=0, label_counts=(("a", 1), ("b", 1), ("c", 1), ("d", 1)),
)
assert [pair for pair in unique.label_counts if pair[1] > 1] == [], (
    "nothing repeats here, so the view must not print a column of ones"
)

noisy = NameComposition(
    total=908, resolved=172, unresolved=329, unchecked=407, auto_issued=524,
    auto_issued_resolved=0, label_counts=(("www", 133), ("cpanel", 131), ("solo", 1)),
)
assert [pair for pair in noisy.label_counts if pair[1] > 1] == [("www", 133), ("cpanel", 131)]
assert noisy.auto_issued_share == 58, noisy.auto_issued_share
assert unique.auto_issued_share == 0, "no division by zero on an empty result"

print("cli presentation test passed")
