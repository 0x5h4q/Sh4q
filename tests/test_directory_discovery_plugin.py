import asyncio
from pathlib import Path

import httpx

from sh4q.config import Sh4qConfig
from sh4q.plugins import DirectoryDiscoveryPlugin
from sh4q.scope import ScopeEngine


class FakeClient:
    def __init__(self):
        self.urls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get_text_bounded(self, url, max_bytes, **kwargs):
        self.urls.append(url)
        body = "not found" if url.endswith("/missing") or url.endswith("/") else "admin page"
        response = httpx.Response(200, headers={"content-type": "text/html"}, content=body, request=httpx.Request("GET", url))
        return response, body, False


def test_directory_probe_authorizes_host_and_classifies_paths(tmp_path: Path):
    words = tmp_path / "paths.txt"
    words.write_text("/\nadmin\nmissing\n../outside\nhttps://evil.test/\n", encoding="utf-8")
    fake = FakeClient()
    plugin = DirectoryDiscoveryPlugin(
        ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"], "ports": [443]})),
        words,
        client_factory=lambda: fake,
    )
    rows = asyncio.run(plugin.execute("example.com"))
    assert fake.urls == [
        "https://example.com/",
        "https://example.com/",
        "https://example.com/admin",
        "https://example.com/missing",
    ]
    assert any(row.kind == "directory_baseline" for row in rows)
    assert any(row.data.get("classification") == "candidate_observation" for row in rows)
    assert any(row.data.get("classification") == "not_found_match" for row in rows)
    assert sum(row.kind == "directory_rejected" for row in rows) == 2


def test_directory_probe_stops_at_request_budget(tmp_path: Path):
    words = tmp_path / "paths.txt"
    words.write_text("one\ntwo\nthree\n", encoding="utf-8")
    fake = FakeClient()
    plugin = DirectoryDiscoveryPlugin(
        ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"], "ports": [443]})),
        words,
        request_budget=2,
        client_factory=lambda: fake,
    )
    rows = asyncio.run(plugin.execute("example.com"))
    assert fake.urls == ["https://example.com/", "https://example.com/one"]
    assert sum(row.kind == "directory_budget_denied" for row in rows) == 2


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory(prefix="sh4q_directory_") as directory:
        test_directory_probe_authorizes_host_and_classifies_paths(Path(directory))
    print("directory discovery plugin test passed")
