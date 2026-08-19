import asyncio
import os

from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine
from sh4q.storage import SQLiteStorage
from sh4q.storage.evidence import SQLiteEvidenceStore
from sh4q.events import EventBus
from sh4q.plugins import Plugin, PluginMetadata, Discovery
from sh4q.scheduler import Scheduler
from sh4q.handlers import make_discovery_handler


execution_order = []


class FakeDNSPlugin(Plugin):
    metadata = PluginMetadata(
        name="fake_dns",
        risk_level="passive",
    )

    async def execute(self, target: str) -> list[Discovery]:
        execution_order.append("fake_dns")

        return [
            Discovery(
                kind="dns_resolution",
                data={
                    "domain": target,
                    "ip": "10.0.0.5",
                },
            )
        ]


class FakeHTTPPlugin(Plugin):
    metadata = PluginMetadata(
        name="fake_http",
        dependencies=["fake_dns"],
        risk_level="active-low",
    )

    async def execute(self, target: str) -> list[Discovery]:
        execution_order.append("fake_http")

        return [
            Discovery(
                kind="http_probe",
                data={
                    "url": f"https://{target}",
                    "status": 200,
                },
            )
        ]


async def main():
    db_path = "/tmp/sh4q_multi_plugin_test.db"

    if os.path.exists(db_path):
        os.remove(db_path)

    cfg = Sh4qConfig(
        **{
            "scope": {
                "targets": [
                    "example.com",
                    "10.0.0.0/24",
                ]
            }
        }
    )

    scope = ScopeEngine(cfg)

    storage = SQLiteStorage(db_path)
    await storage.init()

    evidence_store = SQLiteEvidenceStore(db_path)
    await evidence_store.init()

    bus = EventBus()

    bus.subscribe(
        "discovery",
        make_discovery_handler(
            scope,
            storage,
            evidence_store,
        ),
    )

    bus.start()

    print(
        "-- ordering test: "
        "pass plugins deliberately OUT of order --"
    )

    scheduler = Scheduler(
        plugins=[
            FakeHTTPPlugin(),
            FakeDNSPlugin(),
        ],
        scope=scope,
        bus=bus,
    )

    await scheduler.run("example.com")
    await bus.drain()
    bus.stop()

    print(f"  actual execution order: {execution_order}")
    print(
        "  correctly reordered by dependency: "
        f"{execution_order == ['fake_dns', 'fake_http']}"
    )


asyncio.run(main())


print()
print(
    "-- deliberately BREAK it: "
    "a plugin depending on something that does not exist --"
)


class BrokenDepsPlugin(Plugin):
    metadata = PluginMetadata(
        name="broken",
        dependencies=["nonexistent_plugin"],
    )

    async def execute(self, target: str) -> list[Discovery]:
        return []


async def main2():
    cfg = Sh4qConfig(
        **{
            "scope": {
                "targets": [
                    "example.com",
                ]
            }
        }
    )

    scope = ScopeEngine(cfg)

    storage = SQLiteStorage(
        "/tmp/sh4q_broken_test.db"
    )
    await storage.init()

    bus = EventBus()
    bus.start()

    scheduler = Scheduler(
        plugins=[BrokenDepsPlugin()],
        scope=scope,
        bus=bus,
    )

    try:
        await scheduler.run("example.com")
        print("  ERROR: should never reach here")
    except RuntimeError as e:
        print(f"  correctly rejected: {e}")

    bus.stop()


asyncio.run(main2())