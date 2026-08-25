
from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine


def make_engine():
    cfg = Sh4qConfig(**{
        "scope": {
            "targets": ["example.com", "10.0.0.0/24"],
            "excluded": ["internal.example.com"],
            "ports": [80, 443],
        },
    })
    return ScopeEngine(cfg)


def check(engine, target, port=None):
    d = engine.authorize(target, port)
    status = "ALLOW" if d.allowed else "DENY "
    port_str = f":{port}" if port else ""
    print(f"{status}  {target}{port_str}  -> {d.reason}")


print("-- matching rules --")
engine = make_engine()
check(engine, "example.com")
check(engine, "sub.example.com")
check(engine, "internal.example.com")
check(engine, "evil.com")
check(engine, "10.0.0.5")
check(engine, "10.0.1.5")
check(engine, "example.com", port=22)
print()
print("-- resolved address policy --")
check(engine, "104.26.12.200")
resolved = engine.authorize_resolved_address("104.26.12.200")
print(f"ALLOW  resolved public IP -> {resolved.reason}")
blocked = engine.authorize_resolved_address("127.0.0.1")
print(f"DENY   resolved loopback IP -> {blocked.reason}")
