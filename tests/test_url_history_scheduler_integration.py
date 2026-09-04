import asyncio
import sys
import tempfile
from pathlib import Path

from sh4q.adapters import AdapterContext, ControlledProcessRunner, ExternalAdapterPlugin, URLHistoryAdapter
from sh4q.config import Sh4qConfig
from sh4q.events import EventBus
from sh4q.handlers import make_discovery_handler
from sh4q.scheduler import Scheduler
from sh4q.scope import ScopeEngine


class OfflineURLHistoryAdapter(URLHistoryAdapter):
    def __init__(self):
        super().__init__(executable=sys.executable)

    def build_argv(self, target, context):
        script = "print('https://api.example.com/old?a=1'); print('https://evil.test/out')"
        return (self.executable, "-c", script)

    def build_stdin(self, target, context):
        return None


class EventLog:
    async def record_pending(self, event): pass
    async def mark_processing(self, event_id): pass
    async def mark_completed(self, event_id): pass
    async def mark_failed(self, event_id, error, **kwargs): raise AssertionError(error)
    async def recover_unfinished(self): return []


class Storage:
    def __init__(self): self.nodes, self.relationships = {}, {}
    async def save_node(self, node): self.nodes[node.id] = node
    async def save_relationship(self, relationship): self.relationships[relationship.id] = relationship


class Evidence:
    def __init__(self): self.records = []
    async def append(self, evidence): self.records.append(evidence)


async def main():
    with tempfile.TemporaryDirectory() as directory:
        scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
        storage, evidence = Storage(), Evidence()
        bus = EventBus(event_log=EventLog())
        bus.subscribe("discovery", make_discovery_handler(scope, storage, evidence))
        bus.start()
        plugin = ExternalAdapterPlugin(
            OfflineURLHistoryAdapter(), AdapterContext(scope, Path(directory)),
            ControlledProcessRunner({sys.executable}), timeout=10,
        )
        try:
            decision = await Scheduler([plugin], scope, bus).run("example.com")
            await bus.drain()
        finally:
            await bus.shutdown()
    assert decision.allowed
    assert "url:https://api.example.com/old?a=1" in storage.nodes
    assert "url:https://evil.test/out" not in storage.nodes
    assert len(storage.relationships) == 1
    assert next(iter(storage.relationships.values())).type == "HISTORICAL_URL"
    assert len(evidence.records) == 2
    print("offline URL history scheduler integration test passed")


asyncio.run(main())
