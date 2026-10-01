"""Regression coverage for the authorization perimeter.

ScopeEngine decides every destination Sh4q is allowed to touch, at both
gates. Each assertion below locks in behaviour that was verified against
the engine directly; where the engine cannot parse an input it must fail
closed, and those cases are asserted too.
"""

import asyncio
import contextlib
import io

from sh4q.config import Sh4qConfig
from sh4q.events import Event
from sh4q.handlers import make_discovery_handler
from sh4q.scope import ScopeEngine, ScopeStatus


def engine(**scope) -> ScopeEngine:
    return ScopeEngine(Sh4qConfig(**{"scope": scope}))


def allows(scope_engine, target, port=None) -> bool:
    return scope_engine.authorize(target, port).allowed


class MemoryStorage:
    def __init__(self):
        self.nodes, self.relationships = {}, {}

    async def save_node(self, node):
        self.nodes[node.id] = node

    async def save_relationship(self, relationship):
        self.relationships[relationship.id] = relationship


class MemoryEvidenceStore:
    def __init__(self):
        self.records = []

    async def append(self, evidence):
        self.records.append(evidence)


# --------------------------------------------------------------------------
# authorize: target list, subdomain inheritance, exclusions, ports
# --------------------------------------------------------------------------
scope = engine(
    targets=["example.com", "10.0.0.0/24"],
    excluded=["internal.example.com"],
    ports=[80, 443],
)

assert allows(scope, "example.com")
assert allows(scope, "sub.example.com"), "subdomain inheritance"
assert allows(scope, "a.b.deep.example.com"), "inheritance is not depth limited"

# The inheritance check is endswith("." + pattern). These must not slip through.
assert not allows(scope, "notexample.com"), "suffix without a dot boundary is a different domain"
assert not allows(scope, "example.com.evil.com"), "attacker-controlled parent domain"
assert not allows(scope, "evil.com")
assert not allows(scope, ""), "empty target fails closed"

# Exclusion wins over an otherwise valid match, and inherits to subdomains.
assert not allows(scope, "internal.example.com"), "explicit exclusion"
assert not allows(scope, "deep.internal.example.com"), "exclusion inherits downward"

# Exclusions apply to networks too.
network_scope = engine(targets=["10.0.0.0/16"], excluded=["10.0.5.0/24"])
assert allows(network_scope, "10.0.1.1")
assert not allows(network_scope, "10.0.5.7"), "excluded subnet inside an allowed supernet"

# CIDR membership.
assert allows(scope, "10.0.0.5")
assert not allows(scope, "10.0.1.5"), "outside the allowed network"

# Ports are checked only when supplied; an empty port list means no restriction.
assert allows(scope, "example.com", 80)
assert allows(scope, "example.com", 443)
assert not allows(scope, "example.com", 8080)
assert allows(scope, "example.com", None), "no port supplied means no port check"
assert allows(engine(targets=["example.com"], ports=[]), "example.com", 9999), (
    "an empty port list authorises any port -- change this only deliberately"
)

# Decision objects agree with themselves.
decision = scope.authorize("example.com")
assert decision.status is ScopeStatus.ALLOW and decision.allowed and bool(decision)
refused = scope.authorize("evil.com")
assert refused.status is ScopeStatus.DENY and not refused.allowed and not bool(refused)
assert refused.reason, "a denial must carry a reason"

# --------------------------------------------------------------------------
# normalize_target: everything is compared post-normalization
# --------------------------------------------------------------------------
normalize = ScopeEngine.normalize_target
assert normalize("EXAMPLE.com") == "example.com"
assert normalize("example.com.") == "example.com", "trailing root dot"
assert normalize("0:0:0:0:0:0:0:1") == "::1", "IPv6 canonicalization"
assert normalize("::1") == "::1"
assert normalize("") == ""
assert normalize(".") == ""

assert allows(scope, "EXAMPLE.COM") and allows(scope, "example.com.")

# IDNA equivalence in both directions.
idna_scope = engine(targets=["münchen.de"])
assert allows(idna_scope, "münchen.de")
assert allows(idna_scope, "xn--mnchen-3ya.de"), "punycode form of an in-scope unicode target"
assert allows(idna_scope, "MÜNCHEN.de")

# NFKC folds a fullwidth latin 'e' onto the real ASCII domain, so it is the
# same host and is allowed. Cyrillic lookalikes do not fold, encode to
# different punycode, and must stay out of scope.
assert normalize("ｅxample.com") == "example.com", "fullwidth latin folds to ASCII"
assert allows(scope, "ｅxample.com")
assert not allows(scope, "ехample.com"), "cyrillic homoglyph is a different host"
assert not allows(scope, "exаmple.com"), "single cyrillic 'a' homoglyph"

# Leading-zero IP text is rejected by ipaddress rather than reinterpreted, so
# it can match neither a network nor a hostname. It must fail closed.
assert not allows(engine(targets=["10.0.0.0/24"]), "10.000.000.005")
assert not allows(engine(targets=["10.0.0.0/24"]), "010.0.0.5")
assert not allows(engine(targets=["127.0.0.1"]), "127.000.000.001")

# --------------------------------------------------------------------------
# authorize_resolved_address: address safety policy, separate from hostname scope
# --------------------------------------------------------------------------
strict = engine(targets=["example.com"])
permissive = engine(targets=["example.com"], allow_private_addresses=True)

public = ["8.8.8.8", "2606:4700::1"]
reserved = [
    "10.1.2.3", "192.168.1.1", "172.16.0.1",   # private
    "127.0.0.1", "::1",                         # loopback
    "169.254.1.1", "fe80::1",                   # link-local
    "224.0.0.1",                                # multicast
    "240.0.0.1", "fc00::1",                     # reserved / unique-local
    "0.0.0.0",                                  # unspecified
]

for address in public:
    assert strict.authorize_resolved_address(address).allowed, address
for address in reserved:
    assert not strict.authorize_resolved_address(address).allowed, f"{address} must be denied"
    assert permissive.authorize_resolved_address(address).allowed, (
        f"{address} should be permitted when allow_private_addresses is set"
    )

# A value that is not an address at all is denied under both settings: the
# opt-in flag relaxes address class, never parsing.
for bad in ["not-an-ip", "", "127.000.000.001", "example.com"]:
    assert not strict.authorize_resolved_address(bad).allowed, bad
    assert not permissive.authorize_resolved_address(bad).allowed, (
        f"{bad!r} must stay denied even with allow_private_addresses"
    )

# Hostname scope and address policy are independent: an in-scope hostname
# does not authorise the address it happens to resolve to.
assert allows(strict, "example.com")
assert not strict.authorize_resolved_address("127.0.0.1").allowed


# --------------------------------------------------------------------------
# Gate 2 through the handler: a denial is recorded as evidence, never as inventory
# --------------------------------------------------------------------------
async def gate_two() -> None:
    gate_scope = engine(targets=["example.com"], excluded=["internal.example.com"])
    storage, evidence = MemoryStorage(), MemoryEvidenceStore()
    handler = make_discovery_handler(gate_scope, storage, evidence, stats={})

    denied = [
        ("http_probe", {"final_url": "https://evil.com/", "status": 200}),
        ("http_probe", {"final_url": "https://internal.example.com/", "status": 200}),
        ("subdomain_found", {"hostname": "host.evil.com", "domain": "evil.com"}),
        ("dns_resolution", {"domain": "example.com", "ip": "127.0.0.1"}),
    ]
    with contextlib.redirect_stdout(io.StringIO()):
        for index, (kind, data) in enumerate(denied):
            await handler(Event(id=f"deny-{index}", type="discovery", payload={
                "kind": kind,
                "source_plugin": "test",
                "scan_target": "example.com",
                "data": data,
            }))

    # Evidence is appended before Gate 2 runs, unconditionally: it is the audit
    # trail. The graph is only ever the authorised subset.
    assert len(evidence.records) == len(denied), "every observation must reach evidence"

    # Regression: subdomain_found used to persist its parent domain before any
    # authorization ran, and never authorized the parent at all. Adapter output
    # is untrusted, so an out-of-scope parent could be written into the graph.
    #
    # dns_resolution had the same save-before-authorize shape, reachable only
    # through durable event recovery across scopes; its regression needs a real
    # event log and lives in test_cross_scope_recovery.py.
    assert "domain:evil.com" not in storage.nodes, (
        "the parent of a subdomain discovery must be authorized before it is persisted"
    )
    assert not gate_scope.authorize("evil.com").allowed
    assert "ip:127.0.0.1" not in storage.nodes, "denied address became a node"
    assert not any(node.value == "evil.com" for node in storage.nodes.values())
    assert not any(node.value.startswith("https://evil.com") for node in storage.nodes.values())
    assert not any(
        node.value == "internal.example.com" for node in storage.nodes.values()
    ), "excluded host became a node"
    assert not any(
        "evil.com" in relationship.id or "127.0.0.1" in relationship.id
        for relationship in storage.relationships.values()
    ), "a denied destination must not appear in any relationship"

    # The same handler still persists an authorised discovery, so the assertions
    # above are not passing merely because nothing was ever written.
    storage_ok, evidence_ok = MemoryStorage(), MemoryEvidenceStore()
    allowed_handler = make_discovery_handler(gate_scope, storage_ok, evidence_ok, stats={})
    with contextlib.redirect_stdout(io.StringIO()):
        await allowed_handler(Event(id="allow-0", type="discovery", payload={
            "kind": "http_probe",
            "source_plugin": "test",
            "scan_target": "example.com",
            "data": {"final_url": "https://app.example.com/", "status": 200},
        }))
    assert any(node.value == "app.example.com" for node in storage_ok.nodes.values())
    assert storage_ok.relationships, "an authorised discovery must produce a relationship"

    # An authorised parent with an excluded child: the parent is legitimate
    # inventory and persists, the child does not, and no edge is created.
    with contextlib.redirect_stdout(io.StringIO()):
        await allowed_handler(Event(id="allow-1", type="discovery", payload={
            "kind": "subdomain_found",
            "source_plugin": "ct",
            "scan_target": "example.com",
            "data": {"hostname": "internal.example.com", "domain": "example.com"},
        }))
    assert "domain:example.com" in storage_ok.nodes, "authorised parent persists"
    assert "domain:internal.example.com" not in storage_ok.nodes, "excluded child does not"
    assert not any(
        "internal.example.com" in relationship.id
        for relationship in storage_ok.relationships.values()
    ), "no edge to an excluded child"


asyncio.run(gate_two())

print("scope engine test passed")
