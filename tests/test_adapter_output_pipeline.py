import asyncio
import sys
import tempfile
from pathlib import Path

from sh4q.adapters import (
    AdapterContext,
    ControlledProcessRunner,
    ExternalAdapterPlugin,
    ExternalToolAdapter,
)
from sh4q.config import Sh4qConfig
from sh4q.events import Event
from sh4q.handlers import make_discovery_handler
from sh4q.plugins import Discovery
from sh4q.scope import ScopeEngine


class FakeHostnameAdapter(ExternalToolAdapter):
    name = "fake-hostnames"
    executable = sys.executable
    version_arguments = ("--version",)

    def build_argv(self, target, context):
        script = "print('api.example.com'); print('evil.test')"
        return (self.executable, "-c", script)

    def parse_stdout(self, target, stdout):
        return [
            Discovery(
                kind="subdomain_found",
                data={"domain": target, "hostname": line.strip(), "source": self.name},
            )
            for line in stdout.splitlines()
            if line.strip()
        ]

    def evidence_argv(self, argv):
        return [argv[0], "-c", "<script redacted>"]


class HangingVersionAdapter(FakeHostnameAdapter):
    name = "hanging-version"
    version_arguments = ("-c", "import time; time.sleep(2)")

    def build_argv(self, target, context):
        return (self.executable, "-c", "raise SystemExit('enumeration should be skipped')")


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
    config = Sh4qConfig(**{"scope": {"targets": ["example.com"]}})
    scope = ScopeEngine(config)
    with tempfile.TemporaryDirectory() as directory:
        context = AdapterContext(
            scope=scope,
            output_directory=Path(directory),
        )
        plugin = ExternalAdapterPlugin(
            FakeHostnameAdapter(),
            context,
            ControlledProcessRunner({sys.executable}),
        )
        discoveries = await plugin.execute("example.com")

    assert discoveries[0].kind == "adapter_execution"
    assert discoveries[0].data["returncode"] == 0
    assert discoveries[0].data["tool_version"].startswith("Python ")
    assert discoveries[0].data["argv"][-1] == "<script redacted>"

    evidence = MemoryEvidenceStore()
    storage = MemoryStorage()
    handler = make_discovery_handler(scope, storage, evidence)
    for discovery in discoveries:
        await handler(
            Event(
                type="discovery",
                payload={
                    "kind": discovery.kind,
                    "data": discovery.data,
                    "source_plugin": plugin.metadata.name,
                    "scan_target": "example.com",
                },
            )
        )

    assert len(evidence.records) == 3
    assert "domain:api.example.com" in storage.nodes
    assert "domain:evil.test" not in storage.nodes
    assert len(storage.relationships) == 1

    fast_fail = ExternalAdapterPlugin(
        HangingVersionAdapter(),
        context,
        ControlledProcessRunner({sys.executable}, timeout=0.1),
    )
    skipped = await fast_fail.execute("example.com")
    assert len(skipped) == 1
    assert skipped[0].data["timed_out"] is True
    assert "enumeration skipped" in skipped[0].data["stderr"]
    print("adapter output pipeline test passed")


asyncio.run(main())
