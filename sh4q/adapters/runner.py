from __future__ import annotations

import asyncio
import os
import signal
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


class AdapterExecutionError(Exception):
    pass


@dataclass(frozen=True)
class ProcessResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    output_limited: bool = False


class ControlledProcessRunner:
    """Launch allow-listed tools without a shell under bounded resources."""

    def __init__(
        self,
        allowed_executables: set[str],
        *,
        timeout: float = 30.0,
        max_output_bytes: int = 1_000_000,
        environment: Mapping[str, str] | None = None,
    ):
        if timeout <= 0 or max_output_bytes < 1:
            raise ValueError("timeout and max_output_bytes must be positive")
        self._allowed = {self._resolve_executable(item) for item in allowed_executables}
        self._timeout = timeout
        self._max_output_bytes = max_output_bytes
        self._environment = dict(environment or {})

    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout: float | None = None,
        stdin: bytes | None = None,
    ) -> ProcessResult:
        command = self._validate_argv(argv)
        workdir = cwd.resolve()
        workdir.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(workdir),
            env=self._safe_environment(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            start_new_session=True,
        )
        if stdin is not None:
            process.stdin.write(stdin)
            await process.stdin.drain()
            process.stdin.close()
        stdout_task = asyncio.create_task(self._read_bounded(process.stdout, process))
        stderr_task = asyncio.create_task(self._read_bounded(process.stderr, process))
        timed_out = False
        try:
            await asyncio.wait_for(process.wait(), timeout=timeout or self._timeout)
        except asyncio.TimeoutError:
            timed_out = True
            await self._stop(process)
        except asyncio.CancelledError:
            await self._stop(process)
            stdout_task.cancel()
            stderr_task.cancel()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            raise

        (stdout, stdout_limited), (stderr, stderr_limited) = await asyncio.gather(
            stdout_task, stderr_task
        )
        output_limited = stdout_limited or stderr_limited

        return ProcessResult(
            argv=command,
            returncode=process.returncode if process.returncode is not None else -1,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            duration_seconds=round(time.monotonic() - started, 3),
            timed_out=timed_out,
            output_limited=output_limited,
        )

    async def _read_bounded(self, stream, process):
        retained = bytearray()
        limited = False
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                break
            remaining = self._max_output_bytes - len(retained)
            if remaining > 0:
                retained.extend(chunk[:remaining])
            if len(chunk) > remaining:
                limited = True
                await self._stop(process)
        return bytes(retained), limited

    async def probe_version(
        self,
        executable: str,
        *,
        arguments: Sequence[str] = ("--version",),
        cwd: Path,
    ) -> str:
        result = await self.run(
            (executable, *arguments), cwd=cwd, timeout=min(self._timeout, 5.0)
        )
        if result.timed_out:
            return "[version probe timed out]"
        output = (result.stdout or result.stderr).strip()
        return output.splitlines()[0] if output else f"exit {result.returncode}"

    def _validate_argv(self, argv: Sequence[str]) -> tuple[str, ...]:
        if isinstance(argv, (str, bytes)) or not argv:
            raise AdapterExecutionError("adapter command must be a non-empty argument array")
        command = tuple(argv)
        if any(not isinstance(item, str) or "\0" in item for item in command):
            raise AdapterExecutionError("adapter arguments must be NUL-free strings")
        executable = self._resolve_executable(command[0])
        if executable not in self._allowed:
            raise AdapterExecutionError(f"executable is not allow-listed: {command[0]}")
        return (executable, *command[1:])

    @staticmethod
    def _resolve_executable(executable: str) -> str:
        if "/" in executable:
            return str(Path(executable).resolve())
        resolved = shutil.which(executable)
        if resolved is None:
            raise AdapterExecutionError(f"executable was not found: {executable}")
        return str(Path(resolved).resolve())

    def _safe_environment(self) -> dict[str, str]:
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        }
        environment.update(self._environment)
        return environment

    @staticmethod
    async def _stop(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
            await asyncio.wait_for(process.wait(), timeout=1.0)
        except (ProcessLookupError, asyncio.TimeoutError):
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()
