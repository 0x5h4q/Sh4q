
from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine


def make_engine(budget=1000):
    cfg = Sh4qConfig(**{
        "scope": {
            "targets": ["example.com", "10.0.0.0/24"],
            "excluded": ["internal.example.com"],
            "ports": [80, 443],
        },
        "rate_limit": {"budget": budget},
    })
    return ScopeEngine(cfg)


def check(engine, target, port=None):
    d = engine.authorize(target, port)
    status = "ALLOW" if d.allowed else "DENY "
    port_str = f":{port}" if port else ""
    print(f"{status}  {target}{port_str}  -> {d.reason}")


print("-- matching rules (high budget) --")
engine = make_engine(budget=1000)
check(engine, "example.com")
check(engine, "sub.example.com")
check(engine, "internal.example.com")
check(engine, "evil.com")
check(engine, "10.0.0.5")
check(engine, "10.0.1.5")
check(engine, "example.com", port=22)

print()
print("-- budget exhaustion (separate engine, budget=2) --")
budget_engine = make_engine(budget=2)
check(budget_engine, "example.com")
check(budget_engine, "example.com")
check(budget_engine, "example.com")