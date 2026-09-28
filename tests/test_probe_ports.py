"""Every authorized port is probed, not only the well-known pair.

scope.ports was an authorization filter that nothing consulted when
choosing what to contact, so a config naming a non-standard port
produced a clean scan that reached nothing.
"""

import asyncio

import httpx

from sh4q.config import Sh4qConfig
from sh4q.network import primary_probe_target, probe_targets, probe_url
from sh4q.plugins.http_plugin import HTTPPlugin
from sh4q.scope import ScopeEngine


# --- target selection -----------------------------------------------------
assert probe_targets([80, 443]) == (("http", 80), ("https", 443)), "default scope is unchanged"
assert probe_targets([]) == (("http", 80), ("https", 443)), "any-port scope falls back to well-known"
assert probe_targets([8081]) == (("http", 8081),), "a known plaintext port uses http only"
assert probe_targets([8443]) == (("https", 8443),), "a known TLS port uses https only"
assert probe_targets([9999]) == (("https", 9999), ("http", 9999)), "unknown ports try both schemes"
assert probe_targets([443, 443, 80]) == (("http", 80), ("https", 443)), "duplicates collapse"

# Single-origin stages prefer HTTPS so default scopes keep probing 443.
assert primary_probe_target([80, 443]) == ("https", 443)
assert primary_probe_target([8081]) == ("http", 8081)
assert primary_probe_target([]) == ("https", 443)

# --- URL construction -----------------------------------------------------
assert probe_url("https", "example.com", 443) == "https://example.com"
assert probe_url("http", "example.com", 80) == "http://example.com"
assert probe_url("http", "example.com", 8081) == "http://example.com:8081"
assert probe_url("https", "example.com", 8443, "/") == "https://example.com:8443/"
assert probe_url("https", "::1", 8443) == "https://[::1]:8443", "IPv6 literals must be bracketed"
assert probe_url("http", "127.0.0.1", 80) == "http://127.0.0.1"

# --- the scope exposes its ports ------------------------------------------
scope = ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"], "ports": [8081, 80]}))
assert scope.authorized_ports == (80, 8081)
assert ScopeEngine(Sh4qConfig(scope={"targets": ["x"], "ports": []})).authorized_ports == ()


# --- the HTTP stage probes what the scope authorizes -----------------------
class RecordingClient:
    def __init__(self):
        self.urls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, url, **kwargs):
        self.urls.append(url)
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            content=b"<html><title>ok</title></html>",
            request=httpx.Request("GET", url),
        )


async def probed_urls(ports) -> list[str]:
    client = RecordingClient()
    scope = ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"], "ports": ports}))
    await HTTPPlugin(scope, client_factory=lambda: client).execute("example.com")
    return sorted(client.urls)


async def main() -> None:
    assert await probed_urls([80, 443]) == ["http://example.com", "https://example.com"], (
        "the default scope must keep probing exactly the two well-known origins"
    )
    assert await probed_urls([8081]) == ["http://example.com:8081"], (
        "a non-standard port must actually be probed"
    )
    assert await probed_urls([8080, 8443]) == [
        "http://example.com:8080",
        "https://example.com:8443",
    ]
    assert await probed_urls([]) == ["http://example.com", "https://example.com"]

    # The stage deadline grows with the number of origins so a wide port list
    # cannot be cut short by a deadline sized for two probes.
    narrow = HTTPPlugin(ScopeEngine(Sh4qConfig(scope={"targets": ["x"], "ports": [80, 443]})))
    wide = HTTPPlugin(
        ScopeEngine(Sh4qConfig(scope={"targets": ["x"], "ports": [80, 443, 8080, 8443, 9999]}))
    )
    assert wide.metadata.timeout > narrow.metadata.timeout, (
        f"wide={wide.metadata.timeout} narrow={narrow.metadata.timeout}"
    )

    print("probe ports test passed")


asyncio.run(main())
