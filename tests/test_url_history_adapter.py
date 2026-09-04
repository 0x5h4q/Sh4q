from pathlib import Path

from sh4q.adapters import AdapterContext, URLHistoryAdapter
from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine


config = Sh4qConfig(**{"scope": {"targets": ["example.com"]}})
adapter = URLHistoryAdapter(executable="/opt/tools/waybackurls")
context = AdapterContext(ScopeEngine(config), Path("out"))
assert adapter.build_argv("example.com", context) == ("/opt/tools/waybackurls",)
assert adapter.evidence_argv(adapter.build_argv("example.com", context)) == [
    "/opt/tools/waybackurls", "<stdin>"
]
assert adapter.build_stdin("example.com", context) == b"example.com\n"

discoveries = adapter.parse_stdout(
    "example.com",
    "https://example.com/login?a=1\n"
    "https://api.example.com/v1\n"
    "https://evil.test/leak\n"
    "ftp://example.com/file\n"
    "https://API.EXAMPLE.COM/v1\n",
)
assert discoveries[0].data["urls"] == [
    "https://api.example.com/v1",
    "https://example.com/login?a=1",
]
assert discoveries[0].kind == "url_history_batch"
limited = URLHistoryAdapter(executable="/opt/tools/waybackurls", max_urls=1)
limited_results = limited.parse_stdout(
    "example.com", "https://example.com/a\nhttps://example.com/b\n"
)
assert [item.kind for item in limited_results] == ["url_history_batch", "url_history_truncated"]
assert limited_results[-1].data["available"] == 2
print("URL history adapter test passed")
