import asyncio
import sys
import tempfile
from pathlib import Path

from sh4q.adapters import AdapterExecutionError, ControlledProcessRunner


async def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        cwd = Path(directory)
        runner = ControlledProcessRunner(
            {sys.executable}, timeout=0.2, max_output_bytes=8
        )

        result = await runner.run(
            (sys.executable, "-c", "import os; print(os.getenv('HOME'))"), cwd=cwd
        )
        assert result.returncode == 0
        assert result.stdout.strip() == "None"
        assert not result.timed_out

        limited = await runner.run(
            (sys.executable, "-c", "print('x' * 20)"), cwd=cwd
        )
        assert limited.output_limited
        assert len(limited.stdout.encode()) == 8

        timed = await runner.run(
            (sys.executable, "-c", "import time; time.sleep(2)"), cwd=cwd
        )
        assert timed.timed_out
        assert timed.returncode != 0

        version = await runner.probe_version(
            sys.executable, arguments=("--version",), cwd=cwd
        )
        assert version.startswith("Python ")

        try:
            await runner.run(("/bin/sh", "-c", "echo unsafe"), cwd=cwd)
        except AdapterExecutionError:
            pass
        else:
            raise AssertionError("non-allow-listed executable was launched")

        try:
            await runner.run("not-an-argument-array", cwd=cwd)
        except AdapterExecutionError:
            pass
        else:
            raise AssertionError("string command was accepted")

    print("controlled adapter runner test passed")


asyncio.run(main())
