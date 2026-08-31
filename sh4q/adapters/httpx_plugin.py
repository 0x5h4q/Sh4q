from __future__ import annotations

from sh4q.plugins import Discovery, Plugin, PluginMetadata

from .httpx_fingerprint import HttpxFingerprintAdapter
from .interface import AdapterContext
from .runner import ControlledProcessRunner


class HttpxFingerprintPlugin(Plugin):
    """Run httpx only against HTTP endpoints discovered by this scan."""

    metadata = PluginMetadata(name="httpx-fingerprint", timeout=300.0, risk_level="external-controlled")

    def __init__(self, context: AdapterContext, runner: ControlledProcessRunner, *, executable: str = "httpx", max_endpoints: int = 200):
        self._context = context
        self._runner = runner
        self._adapter = HttpxFingerprintAdapter(executable=executable)
        self._max_endpoints = max(1, max_endpoints)
        self._endpoints: list[str] = []

    def accept_discoveries(self, discoveries: list[Discovery], source_plugin: str | None = None) -> None:
        if source_plugin not in {"http", "discovered-http"}:
            return
        values = {item.data.get("final_url", "") for item in discoveries if item.kind == "http_probe"}
        self._endpoints = sorted(value for value in values if value and self._authorized(value))[: self._max_endpoints]

    def _authorized(self, endpoint: str) -> bool:
        from urllib.parse import urlsplit
        parsed = urlsplit(endpoint)
        return parsed.scheme in {"http", "https"} and bool(parsed.hostname) and self._context.scope.authorize(parsed.hostname).allowed

    async def execute(self, target: str) -> list[Discovery]:
        findings: list[Discovery] = []
        for endpoint in self._endpoints:
            argv = tuple(self._adapter.build_argv(endpoint, self._context))
            result = await self._runner.run(argv, cwd=self._context.output_directory, timeout=120.0)
            findings.append(Discovery("adapter_execution", {"adapter": self._adapter.name, "argv": self._adapter.evidence_argv(result.argv), "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "timed_out": result.timed_out, "output_limited": result.output_limited, "duration_seconds": result.duration_seconds}))
            if result.returncode == 0 and not result.timed_out and not result.output_limited:
                findings.extend(self._adapter.parse_stdout(endpoint, result.stdout))
        return findings
