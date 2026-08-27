import asyncio

from sh4q.config import Sh4qConfig
from sh4q.events import Event
from sh4q.handlers import make_discovery_handler
from sh4q.scope import ScopeEngine


class MemoryEvidenceStore:
    async def append(self, evidence):
        pass


class MemoryStorage:
    def __init__(self):
        self.nodes = {}
        self.relationships = {}

    async def save_node(self, node):
        self.nodes[node.id] = node

    async def save_relationship(self, relationship):
        self.relationships[relationship.id] = relationship


async def publish(handler, source, hostname):
    await handler(
        Event(
            type="discovery",
            payload={
                "kind": "subdomain_found",
                "data": {
                    "domain": "example.com",
                    "hostname": hostname,
                    "source": source,
                },
                "source_plugin": source,
                "scan_target": "example.com",
            },
        )
    )


async def main() -> None:
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    stats = {
        "relationships": 0,
        "discoveries": 0,
        "dns_addresses": 0,
        "http_endpoints": 0,
        "ct_names": 0,
        "adapter_names": 0,
    }
    storage = MemoryStorage()
    handler = make_discovery_handler(scope, storage, MemoryEvidenceStore(), stats=stats)
    await publish(handler, "ct", "shared.example.com")
    await publish(handler, "subfinder", "shared.example.com")
    await publish(handler, "subfinder", "unique.example.com")

    assert stats["ct_names"] == 1
    assert stats["adapter_names"] == 2
    assert stats["discoveries"] == 2
    assert stats["relationships"] == 2
    assert len(storage.relationships) == 2
    print("unique scan reporting test passed")


asyncio.run(main())
