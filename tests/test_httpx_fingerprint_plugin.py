import asyncio
import tempfile
from pathlib import Path

from sh4q.adapters import AdapterContext, HttpxFingerprintPlugin, ProcessResult
from sh4q.config import Sh4qConfig
from sh4q.plugins import Discovery
from sh4q.scope import ScopeEngine


class FakeRunner:
    async def run(self, argv, *, cwd, timeout=None):
        output_path = Path(argv[argv.index("-o") + 1])
        output_path.write_text(
            '{"url":"https://api.example.com/","status_code":200,"tech":["nginx"]}\n',
            encoding="utf-8",
        )
        return ProcessResult(tuple(argv), 0, "", "", 0.1)


async def main():
    config = Sh4qConfig(**{"scope": {"targets": ["example.com"]}})
    scope = ScopeEngine(config)
    with tempfile.TemporaryDirectory() as directory:
        plugin = HttpxFingerprintPlugin(
            AdapterContext(scope, Path(directory)),
            FakeRunner(),
            executable="/opt/tools/httpx",
        )
        plugin.accept_discoveries([
            Discovery("http_probe", {"final_url": "https://api.example.com/"}),
            Discovery("http_probe", {"final_url": "https://evil.test/"}),
        ], "http")
        results = await plugin.execute("example.com")
        assert [item.kind for item in results] == ["adapter_execution", "http_fingerprint"]
        assert results[0].data["input_endpoints"] == 1
        assert results[0].data["reported_responses"] == 1
        assert results[0].data["unreported_endpoints"] == 0
        assert results[0].data["tool_processes"] == 1
        assert results[1].data["technologies"] == ["nginx"]


asyncio.run(main())
print("httpx fingerprint plugin test passed")
