import asyncio
import sys
import tempfile
from pathlib import Path

from sh4q.adapters import (
    AdapterContext,
    AmassPassiveAdapter,
    ControlledProcessRunner,
    ExternalAdapterPlugin,
)
from sh4q.config import Sh4qConfig
from sh4q.events import EventBus
from sh4q.handlers import make_discovery_handler
from sh4q.plugins.discovered_dns_plugin import DiscoveredDNSPlugin
from sh4q.scheduler import Scheduler
from sh4q.scope import ScopeEngine
from sh4q.storage import Node, Relationship
from sh4q.storage.evidence import Evidence


class OfflineAmassAdapter(AmassPassiveAdapter):
    def __init__(self):
        super().__init__(executable=sys.executable)
        self.version_arguments = ("--version",)

    def build_argv(self, target, context):
        script = (
            "print('example.com (FQDN) --> a_record --> api.example.com (FQDN)'); "
            "print('portal.example.com'); print('evil.test')"
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


class MemoryStorage:
    def __init__(self):
        self.nodes = {}
        self.relationships = {}

    async def save_node(self, node: Node):
        self.nodes[node.id] = node

    async def save_relationship(self, relationship: Relationship):
        self.relationships[relationship.id] = relationship


class MemoryEvidenceStore:
    def __init__(self):
        self.records: list[Evidence] = []

    async def append(self, evidence: Evidence):
        self.records.append(evidence)


class MemoryScanAssetStore:
    def __init__(self):
        self.records = []

    async def record(self, scan_run_id, asset_id, relationship_id, source_plugin):
        self.records.append((scan_run_id, asset_id, relationship_id, source_plugin))


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="sh4q_amass_") as directory:
        config = Sh4qConfig(**{"scope": {"targets": ["example.com"]}})
        scope = ScopeEngine(config)
        storage = MemoryStorage()
        evidence = MemoryEvidenceStore()
        scan_assets = MemoryScanAssetStore()

        event_log = MemoryEventLog()
        bus = EventBus(event_log=event_log)
        stats = {}
        bus.subscribe(
            "discovery",
            make_discovery_handler(
                scope,
                storage,
                evidence,
                stats=stats,
                scan_asset_store=scan_assets,
                scan_run_id="scan-amass",
            ),
        )
        bus.start()
        adapter_plugin = ExternalAdapterPlugin(
            OfflineAmassAdapter(),
            AdapterContext(scope, Path(directory)),
            ControlledProcessRunner({sys.executable}),
        )

        async def resolve(name):
            return ["93.184.216.34"] if name in {"api.example.com", "portal.example.com"} else []

        discovered_dns = DiscoveredDNSPlugin(resolver=resolve, scope=scope)
        try:
            decision = await Scheduler(
                [adapter_plugin, discovered_dns],
                scope,
                bus,
                scan_run_id="scan-amass",
            ).run("example.com")
            await bus.drain()
        finally:
            await bus.shutdown()

        assert decision.allowed
        values = {
            storage.nodes[asset_id].value
            for _, asset_id, _, source in scan_assets.records
            if source == "amass-passive" and asset_id in storage.nodes
        }
        assert values == {"api.example.com", "portal.example.com"}, values
        assert "evil.test" not in values

        assert scan_assets.records
        assert {source for _, _, _, source in scan_assets.records} == {
            "amass-passive", "discovered-dns"
        }
        assert len(evidence.records) == 6
        assert event_log.statuses and set(event_log.statuses.values()) == {"COMPLETED"}

    print("offline Amass scheduler integration test passed")


asyncio.run(main())
