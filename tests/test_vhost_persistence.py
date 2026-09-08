import asyncio
import io
import contextlib

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
    async def append(self, evidence):
        pass


async def main():
    scope = ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"]}))
    storage = Storage()
    handler = make_discovery_handler(scope, storage, Evidence(), stats={})
    with contextlib.redirect_stdout(io.StringIO()):
        await handler(Event(type="discovery", payload={
            "kind": "vhost_observation",
            "data": {"candidate": "admin.example.com", "endpoint": "https://example.com/", "status": 403},
            "source_plugin": "vhost-discovery", "scan_target": "example.com",
        }))
    assert "url:https://admin.example.com/" in storage.nodes
    assert storage.nodes["url:https://admin.example.com/"].attributes["probe_endpoint"] == "https://example.com/"
    assert next(iter(storage.relationships.values())).type == "VHOST_SERVES"


if __name__ == "__main__":
    asyncio.run(main())
    print("vhost persistence test passed")
