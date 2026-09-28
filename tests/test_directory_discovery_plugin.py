"""Directory discovery: candidate handling, classification, and budget.

Runs standalone; the pytest entry points are kept so `pytest` still
collects it.
"""

import asyncio
import re
import tempfile
from pathlib import Path

import httpx

from sh4q.config import Sh4qConfig
from sh4q.plugins import DirectoryDiscoveryPlugin
from sh4q.scope import ScopeEngine


NOT_FOUND_PROBE = re.compile(r"/sh4q-[0-9a-f]{32}$")


class FakeClient:
    """Serves a distinct page for /admin and a shared 404 body elsewhere."""

    def __init__(self):
        self.urls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get_text_bounded(self, url, max_bytes, **kwargs):
        self.urls.append(url)
        if url.endswith("/admin"):
            body, status = "admin page", 200
        elif url.endswith("/"):
            body, status = "home page", 200
        else:
            body, status = "not found", 404
        response = httpx.Response(
            status,
            headers={"content-type": "text/html"},
            content=body,
            request=httpx.Request("GET", url),
        )
        return response, body, False


def scope_for(target: str) -> ScopeEngine:
    return ScopeEngine(Sh4qConfig(scope={"targets": [target], "ports": [443]}))


def classification(rows, path):
    for row in rows:
        if row.kind == "directory_observation" and row.data.get("path") == path:
            return row.data.get("classification")
    return None


def test_directory_probe_authorizes_host_and_classifies_paths(tmp_path: Path):
    words = tmp_path / "paths.txt"
    words.write_text("admin\nmissing\n../outside\nhttps://evil.test/\n", encoding="utf-8")
    fake = FakeClient()
    plugin = DirectoryDiscoveryPlugin(scope_for("example.com"), words, client_factory=lambda: fake)
    rows = asyncio.run(plugin.execute("example.com"))

    # Two baseline probes: the root, then a path that cannot exist.
    assert fake.urls[0] == "https://example.com/"
    assert NOT_FOUND_PROBE.search(fake.urls[1]), f"expected a random not-found probe, got {fake.urls[1]}"
    assert fake.urls[2:] == ["https://example.com/admin", "https://example.com/missing"]

    baseline = next(row for row in rows if row.kind == "directory_baseline")
    assert baseline.data["not_found_fingerprint"], "the not-found response must be fingerprinted"
    assert baseline.data["not_found_status"] == 404

    # A real page is a candidate; a genuine 404 is not. Comparing against the
    # root page alone used to report every 404 as a candidate.
    assert classification(rows, "/admin") == "candidate_observation"
    assert classification(rows, "/missing") == "not_found_match"

    # Traversal and absolute URLs never reach the network.
    assert sum(row.kind == "directory_rejected" for row in rows) == 2
    assert not any("outside" in url or "evil.test" in url for url in fake.urls)


def test_soft_404_repeating_the_root_is_not_a_candidate(tmp_path: Path):
    """A server answering unknown paths with its homepage must not look interesting."""

    class SoftNotFoundClient(FakeClient):
        async def get_text_bounded(self, url, max_bytes, **kwargs):
            self.urls.append(url)
            body = "home page"
            response = httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content=body,
                request=httpx.Request("GET", url),
            )
            return response, body, False

    words = tmp_path / "paths.txt"
    words.write_text("anything\n", encoding="utf-8")
    fake = SoftNotFoundClient()
    plugin = DirectoryDiscoveryPlugin(scope_for("example.com"), words, client_factory=lambda: fake)
    rows = asyncio.run(plugin.execute("example.com"))
    assert classification(rows, "/anything") == "not_found_match"


def test_directory_probe_stops_at_request_budget(tmp_path: Path):
    words = tmp_path / "paths.txt"
    words.write_text("one\ntwo\nthree\n", encoding="utf-8")
    fake = FakeClient()
    # Two baselines plus one candidate.
    plugin = DirectoryDiscoveryPlugin(
        scope_for("example.com"), words, request_budget=3, client_factory=lambda: fake
    )
    rows = asyncio.run(plugin.execute("example.com"))
    assert len(fake.urls) == 3, f"budget of 3 must cover both baselines and one candidate: {fake.urls}"
    assert fake.urls[-1] == "https://example.com/one"
    assert sum(row.kind == "directory_budget_denied" for row in rows) == 2


def test_endpoint_honours_the_authorized_port(tmp_path: Path):
    words = tmp_path / "paths.txt"
    words.write_text("admin\n", encoding="utf-8")
    fake = FakeClient()
    plugin = DirectoryDiscoveryPlugin(
        ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"], "ports": [8081]})),
        words,
        client_factory=lambda: fake,
        endpoint_scheme="http",
        endpoint_port=8081,
    )
    asyncio.run(plugin.execute("example.com"))
    assert fake.urls[0] == "http://example.com:8081/", f"got {fake.urls[0]}"
    assert fake.urls[-1] == "http://example.com:8081/admin"


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="sh4q_directory_") as directory:
        root = Path(directory)
        test_directory_probe_authorizes_host_and_classifies_paths(root)
        test_soft_404_repeating_the_root_is_not_a_candidate(root)
        test_directory_probe_stops_at_request_budget(root)
        test_endpoint_honours_the_authorized_port(root)
    print("directory discovery plugin test passed")
