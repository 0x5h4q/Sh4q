from pathlib import Path

from sh4q.adapters import AdapterContext, SubfinderAdapter
from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine


config = Sh4qConfig(**{"scope": {"targets": ["example.com"]}})
adapter = SubfinderAdapter(executable="/opt/tools/subfinder")
context = AdapterContext(ScopeEngine(config), Path("out"))
argv = adapter.build_argv("example.com", context)
assert argv == ("/opt/tools/subfinder", "-silent", "-d", "example.com")
assert adapter.evidence_argv(argv) == ["/opt/tools/subfinder", "-silent", "-d", "<target>"]

discoveries = adapter.parse_stdout(
    "example.com",
    "api.example.com\nAPI.EXAMPLE.COM.\nexample.com\nevil.test\n",
)
assert [item.data["hostname"] for item in discoveries] == [
    "api.example.com",
    "evil.test",
]
print("subfinder adapter test passed")
