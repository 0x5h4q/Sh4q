import asyncio
import sys
import tempfile
from pathlib import Path

from sh4q.adapters import AdapterContext, ControlledProcessRunner, ExternalAdapterPlugin, SubfinderAdapter
from sh4q.config import Sh4qConfig
from sh4q.events import EventBus
from sh4q.handlers import make_discovery_handler
from sh4q.scheduler import Scheduler
from sh4q.scope import ScopeEngine
from sh4q.plugins.discovered_dns_plugin import DiscoveredDNSPlugin


class OfflineSubfinderAdapter(SubfinderAdapter):
    def __init__(self):
        super().__init__(executable=sys.executable)
        self.version_arguments = ("--version",)

    def build_argv(self, target, context):
        script = (
            "print('api.example.com'); print('portal.example.com'); "
            "print('API.EXAMPLE.COM.'); print('evil.test')"
        )
        return (self.executable, "-c", script)


class MemoryEventLog:
    def __init__(self):
        self.statuses = {}

    async def record_pending(self, event):
        self.statuses[event.id] = "PENDING"

    async def mark_processing(self, event_id):
        self.statuses[event_id] = "PROCESSING"

    async def mark_completed(self, event_id):
        self.statuses[event_id] = "COMPLETED"

    async def mark_failed(self, event_id, error, **kwargs):
        self.statuses[event_id] = "FAILED"

    async def recover_unfinished(self):
        return []


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


async def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        config = Sh4qConfig(**{"scope": {"targets": ["example.com"]}})
        scope = ScopeEngine(config)
        storage = MemoryStorage()
        evidence = MemoryEvidenceStore()
        event_log = MemoryEventLog()
        bus = EventBus(event_log=event_log)
        bus.subscribe("discovery", make_discovery_handler(scope, storage, evidence))
        bus.start()
        plugin = ExternalAdapterPlugin(
            OfflineSubfinderAdapter(),
            AdapterContext(scope, Path(directory)),
            ControlledProcessRunner({sys.executable}),
        )
        async def resolve(name):
            if name == "api.example.com":
                return ["93.184.216.34"]
            if name == "portal.example.com":
                return ["127.0.0.1"]
            return []

        discovered_dns = DiscoveredDNSPlugin(resolver=resolve, scope=scope)
        try:
            decision = await Scheduler([plugin, discovered_dns], scope, bus).run("example.com")
            await bus.drain()
        finally:
            await bus.shutdown()

    assert decision.allowed
    assert "domain:api.example.com" in storage.nodes
    assert "domain:portal.example.com" in storage.nodes
    assert "domain:evil.test" not in storage.nodes
    assert "ip:93.184.216.34" in storage.nodes
    assert "ip:127.0.0.1" not in storage.nodes
    assert len(storage.relationships) == 3
    assert len(evidence.records) == 6
    assert set(event_log.statuses.values()) == {"COMPLETED"}
    print("offline Subfinder scheduler integration test passed")


asyncio.run(main())
