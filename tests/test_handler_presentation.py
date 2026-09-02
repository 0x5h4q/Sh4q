import asyncio
import contextlib
import io

from sh4q.config import Sh4qConfig
from sh4q.events import Event
from sh4q.handlers import make_discovery_handler
from sh4q.scope import ScopeEngine


class MemoryStorage:
    def __init__(self):
        self.nodes = {}
        self.relationships = {}

    async def save_node(self, node):
        self.nodes[node.id] = node

    async def save_relationship(self, relationship):
        self.relationships[relationship.id] = relationship


class MemoryEvidenceStore:
    def __init__(self):
        self.records = []

    async def append(self, evidence):
        self.records.append(evidence)


async def main() -> None:
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    storage = MemoryStorage()
    evidence = MemoryEvidenceStore()
    handler = make_discovery_handler(scope, storage, evidence, stats={})
    output = io.StringIO()

    with contextlib.redirect_stdout(output):
        for index in range(12):
            host = f"host-{index}.example.com"
            await handler(Event(type="discovery", payload={
                "kind": "http_probe",
                "source_plugin": "discovered-http",
                "scan_target": "example.com",
                "data": {
                    "final_url": f"https://{host}/",
                    "status": 200,
                },
            }))
        await handler(Event(type="discovery", payload={
            "kind": "http_error",
            "source_plugin": "discovered-http",
            "scan_target": "example.com",
            "data": {"phase": "http", "error": ""},
        }))

    rendered = output.getvalue()
    assert rendered.count("--SERVES-->") == 10
    assert "additional discovered HTTP success results suppressed" in rendered
    assert "FAILED http_error [http]: unknown error" in rendered
    assert len(evidence.records) == 13
    assert len(storage.relationships) == 12
    print("handler presentation test passed")


asyncio.run(main())
