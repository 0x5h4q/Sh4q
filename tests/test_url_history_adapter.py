from pathlib import Path

from sh4q.adapters import AdapterContext, URLHistoryAdapter
from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine


config = Sh4qConfig(**{"scope": {"targets": ["example.com"]}})
adapter = URLHistoryAdapter(executable="/opt/tools/gau")
context = AdapterContext(ScopeEngine(config), Path("out"))
assert adapter.build_argv("example.com", context) == ("/opt/tools/gau", "--subs", "example.com")
assert adapter.evidence_argv(adapter.build_argv("example.com", context)) == [
    "/opt/tools/gau", "--subs", "<target>"
]

discoveries = adapter.parse_stdout(
    "example.com",
    "https://example.com/login?a=1\n"
    "https://api.example.com/v1\n"
    "https://evil.test/leak\n"
    "ftp://example.com/file\n"
    "https://API.EXAMPLE.COM/v1\n",
)
assert [item.data["url"] for item in discoveries] == [
    "https://api.example.com/v1",
    "https://example.com/login?a=1",
]
assert all(item.kind == "url_history_found" for item in discoveries)
print("URL history adapter test passed")
