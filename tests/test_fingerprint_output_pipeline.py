import asyncio

from sh4q.config import Sh4qConfig
from sh4q.events import Event
from sh4q.handlers import make_discovery_handler
from sh4q.scope import ScopeEngine


class MemoryEvidenceStore:
    def __init__(self):
        self.records = []

    async def append(self, evidence):
        self.records.append(evidence)


class MemoryStorage:
    def __init__(self):
        self.nodes = {}
        self.relationships = {}

    async def save_node(self, node):
        self.nodes[node.id] = node

    async def save_relationship(self, relationship):
        self.relationships[relationship.id] = relationship


async def main():
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    storage = MemoryStorage()
    evidence = MemoryEvidenceStore()
    handler = make_discovery_handler(scope, storage, evidence)

    async def publish(endpoint):
        await handler(Event(type="discovery", payload={
            "kind": "http_fingerprint",
            "data": {
                "endpoint": endpoint,
                "status": 200,
                "title": "Example",
                "technologies": ["nginx", "React", "nginx", "WordPress:7.1"],
                "detection_method": "httpx-tech-detect",
                "confidence": "tool-reported",
                "source": "httpx-fingerprint",
            },
            "source_plugin": "httpx-fingerprint",
            "scan_target": "example.com",
        }))

    await publish("https://api.example.com/")
    await publish("https://evil.test/")

    assert "technology:nginx" in storage.nodes
    assert "technology:react" in storage.nodes
    assert "technology:wordpress" in storage.nodes
    assert len(storage.relationships) == 3
    assert all(item.type == "DETECTED_TECHNOLOGY" for item in storage.relationships.values())
    wordpress = next(
        item for item in storage.relationships.values()
        if item.to_id == "technology:wordpress"
    )
    assert wordpress.attributes["version"] == "7.1"
    assert wordpress.attributes["category"] == "cms"
    assert len(evidence.records) == 2
    print("fingerprint output pipeline test passed")


asyncio.run(main())
