import asyncio
from pathlib import Path

from sh4q.adapters import AdapterExecutionError, ProcessResult, validate_projectdiscovery_httpx


class FakeRunner:
    def __init__(self, result):
        self.result = result

    async def run(self, argv, *, cwd, timeout=None):
        assert argv == ("/opt/httpx", "-version")
        return self.result


async def main():
    valid = FakeRunner(ProcessResult(
        ("/opt/httpx", "-version"), 0, "projectdiscovery.io\n[INF] Current Version: v1.9.0\n", "", 0.1
    ))
    version = await validate_projectdiscovery_httpx("/opt/httpx", valid, cwd=Path("."))
    assert version == "[INF] Current Version: v1.9.0"

    incompatible = FakeRunner(ProcessResult(
        ("/opt/httpx", "-version"), 0, "HTTPX command line client\n", "", 0.1
    ))
    try:
        await validate_projectdiscovery_httpx("/opt/httpx", incompatible, cwd=Path("."))
    except AdapterExecutionError as error:
        assert "ProjectDiscovery httpx CLI" in str(error)
    else:
        raise AssertionError("incompatible httpx executable was accepted")


asyncio.run(main())
print("httpx identity test passed")
