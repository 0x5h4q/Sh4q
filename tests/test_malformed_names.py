"""A name that cannot be a hostname is refused, not inherited.

`_matches_one` grants subdomain inheritance with
`target.endswith("." + pattern)`. That rule is satisfied by strings which
are not hostnames at all: `.example.com`, `..example.com`,
`*.example.com`, `**.example.com` all matched the pattern `example.com`
and were authorized, became literal `domain` nodes, and were handed to
DiscoveredDNSPlugin to resolve.

Certificate-transparency connectors already strip a `*.` prefix
(`_clean_hostname`), so wildcard certificate names never reached the
engine from that source -- but `.example.com` passed through their filter
untouched, and "no current emitter does this" is the reasoning that made
dns_resolution (test_cross_scope_recovery.py) and the persistence port
checks (test_persistence_port_policy.py) look safe until they were not.
The perimeter should refuse these on its own.

Fail-closed only: nothing that was authorized before may be refused now.
"""

from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine

engine = ScopeEngine(Sh4qConfig(scope={
    "targets": ["example.com", "10.0.0.0/24", "203.0.113.5"],
    "ports": [443],
}))

# --- names that cannot exist are refused ----------------------------------
for malformed in (
    ".example.com",          # empty leading label
    "..example.com",
    "sub..example.com",      # empty interior label
    "*.example.com",         # wildcard certificate name
    "**.example.com",
    "*.sub.example.com",
    "sub.*.example.com",
    "example.com.",          # handled by normalisation, kept as a guard
):
    decision = engine.authorize(malformed)
    if malformed == "example.com.":
        assert decision.allowed, "a trailing dot is normalised away, not malformed"
        continue
    assert not decision.allowed, f"{malformed!r} is not a hostname and must be refused"
    assert "hostname" in decision.reason or "not in the allowed" in decision.reason, (
        f"{malformed!r}: {decision.reason}"
    )

# --- everything that worked before still works -----------------------------
for valid in (
    "example.com",
    "sub.example.com",
    "deep.nested.sub.example.com",
    "a-b.example.com",
    "1.example.com",
    "xn--exmple-cua.example.com",
):
    assert engine.authorize(valid).allowed, f"{valid!r} must stay authorized"

# IPs and CIDR membership are untouched: an address has no hostname labels.
for address in ("10.0.0.7", "10.0.0.0", "203.0.113.5"):
    assert engine.authorize(address).allowed, f"{address!r} must stay authorized"
for outside in ("10.0.1.7", "203.0.113.6"):
    assert not engine.authorize(outside).allowed, f"{outside!r} must stay refused"

# Exclusions still win, and a malformed exclusion entry cannot be used to
# smuggle a name past the allow-list.
excluding = ScopeEngine(Sh4qConfig(scope={
    "targets": ["example.com"], "excluded": ["secret.example.com"],
}))
assert not excluding.authorize("secret.example.com").allowed
assert not excluding.authorize(".secret.example.com").allowed
assert excluding.authorize("open.example.com").allowed

# The address-safety policy is a separate call and keeps accepting addresses.
assert ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"]})).authorize_resolved_address(
    "93.184.216.34"
).allowed

# --- a malformed pattern in the config cannot widen the scope --------------
# An operator typo like "- .example.com" must not become a rule that matches
# everything ending in ".example.com" more loosely than the real pattern.
typo = ScopeEngine(Sh4qConfig(scope={"targets": [".example.com"]}))
assert not typo.authorize("evil.com").allowed
assert not typo.authorize(".example.com").allowed, (
    "a malformed pattern must not authorize the malformed name either"
)

print("malformed name test passed")
