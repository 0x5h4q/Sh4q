import asyncio
from pathlib import Path

import httpx

from sh4q.adapters import AdapterExecutionError
from sh4q.application import run_scan
from sh4q.config import Sh4qConfig
from sh4q.plugins import VhostDiscoveryPlugin
from sh4q.scope import ScopeEngine


class FakeClient:
    def __init__(self):
        self.hosts = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get_text_bounded(self, url, max_bytes, **kwargs):
        host = kwargs["headers"]["Host"]
        self.hosts.append(host)
        body = b"default" if host in {"example.com", "admin.example.com"} else host.encode()
        response = httpx.Response(200, headers={"content-type": "text/html"}, content=body, request=httpx.Request("GET", url))
        return response, body.decode(), False


def test_vhost_candidates_are_bounded_scoped_and_classified(tmp_path: Path):
    candidate_file = tmp_path / "vhosts.txt"
    candidate_file.write_text("admin\nadmin.example.com\nevil.test\n" + "x\n" * 600)
    fake = FakeClient()
    plugin = VhostDiscoveryPlugin(
        ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"], "ports": [443]})),
        candidate_file,
        max_candidates=4,
        client_factory=lambda: fake,
        request_interval=0,
    )
    rows = asyncio.run(plugin.execute("example.com"))
    assert fake.hosts == ["example.com", "admin.example.com", "x.example.com"]
    assert rows[0].kind == "vhost_baseline"
    assert any(row.kind == "vhost_rejected" and row.data["candidate"] == "evil.test" for row in rows)
    assert any(row.data.get("classification") == "default_vhost_match" for row in rows)


def test_vhost_missing_file_fails_before_requests(tmp_path: Path):
    plugin = VhostDiscoveryPlugin(
        ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"]})),
        tmp_path / "missing.txt",
    )
    try:
        asyncio.run(plugin.execute("example.com"))
    except ValueError as error:
        assert "candidate file not found" in str(error)
    else:
        raise AssertionError("missing candidate file should fail closed")


def test_vhost_accepts_explicit_scan_candidates():
    fake = FakeClient()
    plugin = VhostDiscoveryPlugin(
        ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"], "ports": [443]})),
        candidates=["admin.example.com"],
        client_factory=lambda: fake,
        request_interval=0,
    )
    rows = asyncio.run(plugin.execute("example.com"))
    assert fake.hosts == ["example.com", "admin.example.com"]
    assert any(row.kind == "vhost_observation" for row in rows)


def test_vhost_timeout_budget_scales_with_candidate_bound():
    plugin = VhostDiscoveryPlugin(
        ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"]})),
        candidates=["a.example.com"] * 500,
        request_interval=1.0,
    )
    assert plugin.metadata.timeout >= 531


def test_vhost_collects_current_scan_candidates_when_no_source_given():
    fake = FakeClient()
    plugin = VhostDiscoveryPlugin(
        ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"]})),
        client_factory=lambda: fake,
        request_interval=0,
    )
    plugin.accept_discoveries([
        __import__("sh4q.plugins", fromlist=["Discovery"]).Discovery(
            "subdomain_found", {"hostname": "admin.example.com"}
        )
    ], "ct")
    rows = asyncio.run(plugin.execute("example.com"))
    assert fake.hosts == ["example.com", "admin.example.com"]
    assert any(row.data.get("candidate") == "admin.example.com" for row in rows)


def test_scan_preflight_rejects_missing_vhost_file(tmp_path: Path):
    missing = tmp_path / "missing-scan-candidates.txt"
    try:
        asyncio.run(
            run_scan(
                "example.com",
                include_vhosts=True,
                vhosts_file=str(missing),
            )
        )
    except AdapterExecutionError as error:
        assert str(missing) in str(error)
    else:
        raise AssertionError("scan should stop before starting without its candidate file")


if __name__ == "__main__":
    import tempfile

    root = Path(tempfile.mkdtemp(prefix="sh4q_vhost_"))
    test_vhost_candidates_are_bounded_scoped_and_classified(root)
    test_vhost_missing_file_fails_before_requests(root)
    test_vhost_accepts_explicit_scan_candidates()
    test_vhost_collects_current_scan_candidates_when_no_source_given()
    test_scan_preflight_rejects_missing_vhost_file(root)
    print("vhost discovery plugin test passed")
