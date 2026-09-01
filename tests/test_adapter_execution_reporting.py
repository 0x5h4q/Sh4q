import asyncio
import io
from contextlib import redirect_stdout

from sh4q.config import Sh4qConfig
from sh4q.events import Event
from sh4q.handlers import make_discovery_handler
from sh4q.scope import ScopeEngine


class NullStore:
    async def append(self, item):
        pass

    async def save_node(self, item):
        pass

    async def save_relationship(self, item):
        pass


async def main():
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
    handler = make_discovery_handler(scope, NullStore(), NullStore())
    event = Event(type="discovery", payload={
        "kind": "adapter_execution",
        "source_plugin": "subfinder",
        "scan_target": "example.com",
        "data": {
            "adapter": "subfinder",
            "timed_out": True,
            "duration_seconds": 30.0,
            "output_limited": False,
            "returncode": -15,
            "stdout": "",
            "stderr": "",
        },
    })
    output = io.StringIO()
    with redirect_stdout(output):
        await handler(event)
    assert "[-] FAILED subfinder: execution timed out after 30.0s" in output.getvalue()
    print("adapter execution reporting test passed")


asyncio.run(main())
