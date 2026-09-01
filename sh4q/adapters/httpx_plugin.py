from __future__ import annotations

from sh4q.plugins import Discovery, Plugin, PluginMetadata

from .httpx_fingerprint import HttpxFingerprintAdapter
from .interface import AdapterContext
from .runner import ControlledProcessRunner


class HttpxFingerprintPlugin(Plugin):
    """Run httpx only against HTTP endpoints discovered by this scan."""

    metadata = PluginMetadata(name="httpx-fingerprint", timeout=150.0, risk_level="external-controlled")

    def __init__(self, context: AdapterContext, runner: ControlledProcessRunner, *, executable: str = "httpx", max_endpoints: int = 200, timeout: float = 120.0):
        self._context = context
        self._runner = runner
        self._adapter = HttpxFingerprintAdapter(executable=executable)
        self._max_endpoints = max(1, max_endpoints)
        self._timeout = timeout
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
        if not self._endpoints:
            return []
        input_file = (self._context.output_directory / "httpx-endpoints.txt").resolve()
        output_file = (self._context.output_directory / "httpx-results.jsonl").resolve()
        input_file.write_text("\n".join(self._endpoints) + "\n", encoding="utf-8")
        output_file.unlink(missing_ok=True)
        argv = (
            self._adapter.executable,
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-l",
            str(input_file),
            "-o",
            str(output_file),
        )
        result = await self._runner.run(argv, cwd=self._context.output_directory, timeout=self._timeout)
        output = result.stdout
        if output_file.exists():
            output = output_file.read_text(encoding="utf-8", errors="replace")
        reported = sum(1 for line in output.splitlines() if line.strip())
        findings = [Discovery("adapter_execution", {"adapter": self._adapter.name, "argv": self._adapter.evidence_argv(result.argv), "returncode": result.returncode, "stdout": output, "stderr": result.stderr, "timed_out": result.timed_out, "output_limited": result.output_limited, "duration_seconds": result.duration_seconds, "input_endpoints": len(self._endpoints), "reported_responses": reported, "unreported_endpoints": max(0, len(self._endpoints) - reported), "tool_processes": 1})]
        if result.returncode == 0 and not result.timed_out and not result.output_limited:
            findings.extend(self._adapter.parse_stdout("batch", output))
        return findings
