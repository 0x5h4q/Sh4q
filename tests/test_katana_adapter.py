from pathlib import Path

from sh4q.adapters import AdapterContext, KatanaAdapter
from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine


scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["example.com"]}}))
adapter = KatanaAdapter(executable="/opt/katana", depth=1, crawl_duration="10s")
argv = adapter.build_argv("example.com", AdapterContext(scope, Path("out")))
assert argv == (
    "/opt/katana", "-silent", "-u", "https://example.com/", "-jc", "-xhr", "-j",
    "-d", "1", "-ct", "10s", "-max-response-size", "262144", "-timeout", "10",
    "-retry", "1", "-dr",
)

findings = adapter.parse_stdout(
    "example.com",
    '{"request":{"url":"https://example.com/app.js"}}\n'
    '{"xhr":{"url":"https://cdn.example.com/chunk.js"}}\n'
    "https://outside.test/secret\n"
    "not-a-url\n",
)
assert [(item.kind, item.data["value"]) for item in findings] == [
    ("javascript_script_url", "https://cdn.example.com/chunk.js"),
    ("javascript_script_url", "https://example.com/app.js"),
]
assert [item.data["value"] for item in findings] == [
    "https://cdn.example.com/chunk.js",
    "https://example.com/app.js",
]
assert adapter.evidence_argv(argv) == ["/opt/katana", "<bounded katana arguments>"]
print("Katana adapter test passed")
