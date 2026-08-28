from pathlib import Path

from sh4q.adapters import AdapterContext, HttpxFingerprintAdapter
from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine


config = Sh4qConfig(**{"scope": {"targets": ["example.com"]}})
context = AdapterContext(ScopeEngine(config), Path("out"))
adapter = HttpxFingerprintAdapter(executable="/opt/tools/httpx")
argv = adapter.build_argv("https://api.example.com/", context)
assert argv == (
    "/opt/tools/httpx",
    "-silent",
    "-json",
    "-status-code",
    "-title",
    "-tech-detect",
    "-u",
    "https://api.example.com/",
)
assert adapter.evidence_argv(argv)[-1] == "<endpoint>"

discoveries = adapter.parse_stdout(
    "https://api.example.com/",
    '{"url":"https://api.example.com/","status_code":200,"title":"API","tech":["nginx","React","nginx"]}\n',
)
assert len(discoveries) == 1
assert discoveries[0].kind == "http_fingerprint"
assert discoveries[0].data == {
    "endpoint": "https://api.example.com/",
    "status": 200,
    "title": "API",
    "technologies": ["React", "nginx"],
    "detection_method": "httpx-tech-detect",
    "confidence": "tool-reported",
    "source": "httpx-fingerprint",
}
print("httpx fingerprint adapter test passed")
