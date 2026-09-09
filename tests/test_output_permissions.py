import asyncio
import os
import stat
import tempfile
from pathlib import Path

from sh4q.application.scan_runner import _secure_output_paths


async def main():
    with tempfile.TemporaryDirectory(prefix="sh4q_permissions_") as directory:
        output = Path(directory) / "output"
        database = output / "sh4q.db"
        output.mkdir()
        database.touch()
        _secure_output_paths(str(output), str(database))
        assert stat.S_IMODE(output.stat().st_mode) == 0o700
        assert stat.S_IMODE(database.stat().st_mode) == 0o600


if __name__ == "__main__":
    asyncio.run(main())
    print("output permission test passed")
