import asyncio
import os
import time

from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine
from sh4q.storage import SQLiteStorage
from sh4q.events import EventBus
from sh4q.scheduler import Scheduler
from sh4q.handlers import make_discovery_handler
from sh4q.plugins.dns_plugin import DNSPlugin
from sh4q.plugins.http_plugin import HTTPPlugin

execute_calls = []


class TrackedDNSPlugin(DNSPlugin):
    async def execute(self, target):
        execute_calls.append("dns")
        return await super().execute(target)


class TrackedHTTPPlugin(HTTPPlugin):
    async def execute(self, target):
        execute_calls.append("http")
        return await super().execute(target)


async def test_dedup():
    db_path = "/tmp/sh4q_hardening.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    cfg = Sh4qConfig(**{"scope": {"targets": ["example.com", "0.0.0.0/0"]}})
    scope = ScopeEngine(cfg)
    storage = SQLiteStorage(db_path)
    await storage.init()
    bus = EventBus()
    bus.subscribe("discovery", make_discovery_handler(scope, storage))
    bus.start()
    scheduler = Scheduler(plugins=[DNSPlugin(), HTTPPlugin()], scope=scope, bus=bus)

    print("=== TEST 1: repeated execution — no duplicates, correct merge ===")
    start = time.monotonic()
    await scheduler.run("example.com")
    await bus.drain()
    print(f"  first run: {time.monotonic()-start:.2f}s")

    domain_after_1 = await storage.get_node("domain:example.com")
    rels_after_1 = await storage.get_relationships("domain:example.com")
    first_seen_1 = domain_after_1.first_seen
    print(f"  relationships after run 1: {len(rels_after_1)}")

    await asyncio.sleep(1.1)
    start = time.monotonic()
    await scheduler.run("example.com")
    await bus.drain()
    print(f"  second run: {time.monotonic()-start:.2f}s")

    domain_after_2 = await storage.get_node("domain:example.com")
    rels_after_2 = await storage.get_relationships("domain:example.com")
    print(f"  relationships after run 2: {len(rels_after_2)} (should match run 1)")
    print(f"  first_seen unchanged: {domain_after_2.first_seen == first_seen_1}")
    print(f"  last_seen updated: {domain_after_2.last_seen != domain_after_1.last_seen}")

    bus.stop()


async def test_denied_target():
    db_path = "/tmp/sh4q_denied_test.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    cfg = Sh4qConfig(**{"scope": {"targets": ["example.com", "0.0.0.0/0"]}})
    scope = ScopeEngine(cfg)
    storage = SQLiteStorage(db_path)
    await storage.init()
    bus = EventBus()
    bus.subscribe("discovery", make_discovery_handler(scope, storage))
    bus.start()

    scheduler = Scheduler(plugins=[TrackedDNSPlugin(), TrackedHTTPPlugin()], scope=scope, bus=bus)
    print()
    print("=== TEST 2: fully unauthorized target ===")
    await scheduler.run("evil.com")
    await bus.drain()
    bus.stop()

    print(f"  plugins that actually executed: {execute_calls} (should be empty)")
    domain_node = await storage.get_node("domain:evil.com")
    print(f"  anything saved for evil.com: {domain_node is not None} (should be False)")


async def main():
    await test_dedup()
    await test_denied_target()


asyncio.run(main())