from __future__ import annotations

from sh4q.plugins import Discovery, Plugin, PluginMetadata

from .interface import AdapterContext, ExternalToolAdapter
from .runner import ControlledProcessRunner


class ExternalAdapterPlugin(Plugin):
    """Run an external adapter and return evidence plus parsed discoveries."""

    def __init__(
        self,
        adapter: ExternalToolAdapter,
        context: AdapterContext,
        runner: ControlledProcessRunner,
        *,
        timeout: float = 30.0,
    ):
        self.adapter = adapter
        self.context = context
        self.runner = runner
        self.metadata = PluginMetadata(
            name=adapter.name,
            version=adapter.version,
            timeout=timeout + 6.0,
            risk_level="external-controlled",
        )
        self._process_timeout = timeout

    async def execute(self, target: str) -> list[Discovery]:
        argv = tuple(self.adapter.build_argv(target, self.context))
        tool_version = await self.runner.probe_version(
            self.adapter.executable,
            arguments=self.adapter.version_arguments,
            cwd=self.context.output_directory,
        )
        result = await self.runner.run(
            argv,
            cwd=self.context.output_directory,
            timeout=self._process_timeout,
        )
        execution = Discovery(
            kind="adapter_execution",
            data={
                "adapter": self.adapter.name,
                "adapter_version": self.adapter.version,
                "tool_version": tool_version,
                "argv": self.adapter.evidence_argv(result.argv),
                "returncode": result.returncode,
                "duration_seconds": result.duration_seconds,
                "timed_out": result.timed_out,
                "output_limited": result.output_limited,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
        )
        if result.returncode != 0 or result.timed_out or result.output_limited:
            return [execution]
        return [execution, *self.adapter.parse_stdout(target, result.stdout)]
