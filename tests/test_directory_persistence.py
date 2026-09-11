import asyncio
import contextlib
import io

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
    storage = Storage()
    handler = make_discovery_handler(
        ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"]})),
        storage,
        Evidence(),
        stats={},
    )
    with contextlib.redirect_stdout(io.StringIO()):
        await handler(Event(type="discovery", payload={
            "kind": "directory_observation",
            "data": {
                "url": "https://example.com/admin",
                "path": "/admin",
                "status": 200,
                "classification": "candidate_observation",
            },
            "source_plugin": "directory-discovery",
            "scan_target": "example.com",
        }))
    assert "url:https://example.com/admin" in storage.nodes
    assert any(item.type == "DIRECTORY_OBSERVATION" for item in storage.relationships.values())


if __name__ == "__main__":
    asyncio.run(main())
    print("directory persistence test passed")
