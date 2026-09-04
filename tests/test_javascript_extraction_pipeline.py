import asyncio

from sh4q.config import Sh4qConfig
from sh4q.events import Event
from sh4q.handlers import make_discovery_handler
from sh4q.scope import ScopeEngine


class Storage:
    def __init__(self):
        self.nodes = {}
        self.relationships = {}

    async def save_node(self, node):
        self.nodes[node.id] = node

    async def save_relationship(self, relationship):
        self.relationships[relationship.id] = relationship


class Evidence:
    def __init__(self):
        self.records = []

    async def append(self, evidence):
        self.records.append(evidence)


async def main():
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    storage, evidence, stats = Storage(), Evidence(), {}
    handler = make_discovery_handler(scope, storage, evidence, stats=stats, scan_run_id="scan-1")

    await handler(Event(type="discovery", payload={
        "kind": "javascript_endpoint_reference",
        "source_plugin": "javascript-extraction",
        "scan_target": "example.com",
        "scan_run_id": "scan-1",
        "data": {"value": "https://api.example.com/v1/users", "source_endpoint": "https://example.com/"},
    }))
    assert "url:https://api.example.com/v1/users" in storage.nodes
    assert len(storage.relationships) == 1
    assert next(iter(storage.relationships.values())).type == "JAVASCRIPT_REFERENCE"

    await handler(Event(type="discovery", payload={
        "kind": "javascript_endpoint_reference",
        "source_plugin": "javascript-extraction",
        "scan_target": "example.com",
        "scan_run_id": "scan-1",
        "data": {"value": "https://outside.invalid/secret", "source_endpoint": "https://example.com/"},
    }))
    assert "url:https://outside.invalid/secret" not in storage.nodes
    assert len(storage.relationships) == 1

    await handler(Event(type="discovery", payload={
        "kind": "javascript_secret_like_pattern",
        "source_plugin": "javascript-extraction",
        "scan_target": "example.com",
        "scan_run_id": "scan-1",
        "data": {"value": "aws_access_key_id", "pattern": "aws_access_key_id"},
    }))
    assert len(evidence.records) == 3
    assert stats["javascript_references"] == 1
    print("javascript extraction pipeline test passed")


asyncio.run(main())
