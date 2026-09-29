"""Which names get resolved when there are more than the bound.

Taking the alphabetically first N is deterministic and systematically
biased. On a real target, 500 names drawn from 1211 spent 62% of the
budget on hostnames beginning with "c" and stopped at "mail.cicadi" --
nothing from n to z was ever looked at. Adding a second discovery source
made this worse, not better: 1513 candidate names produced 118 live
hosts where 907 names had produced 171.

Selection must stay deterministic, so a scan can be repeated, while
sampling the whole range rather than its first slice.
"""

import collections
import string

from sh4q.config import Sh4qConfig
from sh4q.plugins.discovered_dns_plugin import DiscoveredDNSPlugin
from sh4q.plugins.discovery import Discovery
from sh4q.scope import ScopeEngine


select = DiscoveredDNSPlugin._select


def names_from(letters: str, per_letter: int, source: str) -> dict[str, set[str]]:
    return {f"{c}{i:03d}.example.com": {source} for c in letters for i in range(per_letter)}


# --- the bias this replaces ------------------------------------------------
crowded = names_from("abc", 400, "ct")
crowded.update(names_from(string.ascii_lowercase[3:], 14, "subfinder"))

alphabetical = sorted(crowded)[:500]
spread = select(crowded, 500)

assert len({n[0] for n in alphabetical}) < 5, "the old behaviour reached very few letters"
assert len({n[0] for n in spread}) == 26, (
    f"the sample must cover the whole range, reached {sorted({n[0] for n in spread})}"
)
worst = collections.Counter(n[0] for n in spread).most_common(1)[0][1]
assert worst < len(spread) // 2, f"no single letter may dominate the budget: {worst}/500"
assert len(spread) == 500, len(spread)


# --- deterministic: a repeated scan resolves the same names ----------------
assert select(crowded, 500) == spread, "selection must be reproducible"
shuffled = dict(reversed(list(crowded.items())))
assert select(shuffled, 500) == spread, "insertion order must not change the outcome"


# --- corroboration and operator intent win over sampling -------------------
sources = {f"single{i:03d}.example.com": {"ct"} for i in range(50)}
sources.update({f"both{i:03d}.example.com": {"ct", "subfinder"} for i in range(5)})
sources["asked.example.com"] = {"operator"}

picked = select(sources, 10)
assert "asked.example.com" in picked, "a name the operator supplied is never sampled out"
for i in range(5):
    assert f"both{i:03d}.example.com" in picked, (
        "a name two sources agree on outranks one only a single source produced"
    )
assert len(picked) == 10

# Under the bound, everything is kept and nothing is sampled away.
small = {f"h{i}.example.com": {"ct"} for i in range(4)}
assert select(small, 500) == sorted(small), select(small, 500)
assert select({}, 10) == []


# --- the plugin applies it, and scope still comes first --------------------
scope = ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"]}))
plugin = DiscoveredDNSPlugin(max_names=3, scope=scope)
plugin.accept_discoveries(
    [Discovery("subdomain_found", {"hostname": f"{c}.example.com"}) for c in "abcdefgh"]
    + [Discovery("subdomain_found", {"hostname": "out.of.scope.test"})],
    "ct",
)
assert len(plugin._names) == 3, plugin._names
assert not any(n.endswith(".test") for n in plugin._names), (
    "an out-of-scope name must be filtered before it can be sampled"
)
assert plugin._names[-1] > "c.example.com", (
    f"the sample must reach past the first few alphabetically: {plugin._names}"
)

# An operator list survives a flood of discovered names.
plugin = DiscoveredDNSPlugin(max_names=5, scope=scope, names=["mine.example.com"])
plugin.accept_discoveries(
    [Discovery("subdomain_found", {"hostname": f"a{i:03d}.example.com"}) for i in range(200)],
    "ct",
)
assert "mine.example.com" in plugin._names, plugin._names

print("name selection test passed")
