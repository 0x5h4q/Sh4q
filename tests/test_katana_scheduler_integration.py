import asyncio
import sys
import tempfile
from pathlib import Path

from sh4q.adapters import AdapterContext, ControlledProcessRunner, ExternalAdapterPlugin, KatanaAdapter
from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine


class OfflineKatanaAdapter(KatanaAdapter):
    name = "katana"
    version_arguments = ("-c", "print('katana test')")

    def build_argv(self, target: str, context: AdapterContext):
        output = (
            "https://example.com/app.js\n"
            "https://api.example.com/v1/users\n"
            "https://outside.test/secret\n"
        )
        return (self.executable, "-c", f"print({output!r}, end='')")


async def main() -> None:
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    with tempfile.TemporaryDirectory() as directory:
        executable = sys.executable
        plugin = ExternalAdapterPlugin(
            OfflineKatanaAdapter(executable=executable),
            AdapterContext(scope, Path(directory)),
            ControlledProcessRunner({executable}),
            timeout=5,
        )
        findings = await plugin.execute("example.com")

    execution = findings[0]
    assert execution.kind == "adapter_execution"
    assert execution.data["returncode"] == 0
    assert execution.data["tool_version"] == "katana test"
    assert [item.data["value"] for item in findings[1:]] == [
        "https://api.example.com/v1/users",
        "https://example.com/app.js",
    ]
    print("Katana scheduler integration test passed")


asyncio.run(main())
