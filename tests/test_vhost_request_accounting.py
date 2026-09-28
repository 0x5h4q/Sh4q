"""Virtual-host probes must be counted against the run's request budget.

The vhost design record requires the scheduler to account for admitted,
completed, failed, and budget-denied requests. The stage previously built
its HTTP client without the shared RequestLimiter, so up to 500 probes
ran outside the configured budget and never appeared in request metrics.
"""

import asyncio

import httpx

from sh4q.config import Sh4qConfig
from sh4q.network import RequestLimiter
from sh4q.plugins import VhostDiscoveryPlugin
from sh4q.scope import ScopeEngine


class FakeLimitedClient:
    """Stands in for ScopedHTTPClient, consuming limiter permits as it would."""

    def __init__(self, limiter):
        self._limiter = limiter
        self.requested = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get_text_bounded(self, url, max_bytes, **kwargs):
        permit = await self._limiter.acquire()
        if permit is None:
            from sh4q.network import ScopedHTTPError

            raise ScopedHTTPError("request budget exhausted", phase="limit")
        async with permit:
            host = kwargs["headers"]["Host"]
            self.requested.append(host)
            body = host.encode()
            permit.succeeded()
            return (
                httpx.Response(
                    200,
                    headers={"content-type": "text/html"},
                    content=body,
                    request=httpx.Request("GET", url),
                ),
                body.decode(),
                False,
            )


def scope_for(target: str) -> ScopeEngine:
    return ScopeEngine(Sh4qConfig(scope={"targets": [target], "ports": [443]}))


async def main() -> None:
    # The constructor must accept the shared limiter and hand it to its client.
    limiter = RequestLimiter(3, 100.0, 1000)
    plugin = VhostDiscoveryPlugin(scope_for("example.com"), candidates=["a"], limiter=limiter)
    assert plugin._client_factory()._limiter is limiter, (
        "the default vhost client must carry the run's limiter"
    )

    # With the budget smaller than the candidate list, the excess is refused
    # rather than quietly sent, and refusals are labelled as budget denials
    # rather than transport errors.
    budget = 3
    limiter = RequestLimiter(3, 100.0, budget)
    client = FakeLimitedClient(limiter)
    plugin = VhostDiscoveryPlugin(
        scope_for("example.com"),
        candidates=[f"host{index}" for index in range(6)],
        limiter=limiter,
        client_factory=lambda: client,
        request_interval=0,
    )
    discoveries = await plugin.execute("example.com")
    kinds: dict[str, int] = {}
    for discovery in discoveries:
        kinds[discovery.kind] = kinds.get(discovery.kind, 0) + 1

    assert len(client.requested) == budget, (
        f"exactly the budget should be spent, sent {len(client.requested)} of {budget}"
    )
    assert kinds.get("vhost_budget_denied") == 4, (
        f"remaining candidates must be denied, got {kinds}"
    )
    assert "vhost_error" not in kinds, "a budget denial is a policy outcome, not an error"

    metrics = await limiter.metrics()
    assert metrics.admitted == budget, f"probes must be admitted through the limiter: {metrics}"
    assert metrics.denied == 4, f"refusals must be counted: {metrics}"
    assert metrics.completed == budget, f"successful probes must be recorded: {metrics}"

    # Out-of-scope candidates are refused before any permit is taken, so a
    # denied candidate never consumes budget that an authorised one could use.
    limiter = RequestLimiter(3, 100.0, 10)
    client = FakeLimitedClient(limiter)
    plugin = VhostDiscoveryPlugin(
        scope_for("example.com"),
        candidates=["good", "evil.test", "also-good"],
        limiter=limiter,
        client_factory=lambda: client,
        request_interval=0,
    )
    discoveries = await plugin.execute("example.com")
    assert "evil.test" not in client.requested, "an out-of-scope candidate must not be probed"
    assert any(
        d.kind == "vhost_rejected" and d.data["candidate"] == "evil.test" for d in discoveries
    )
    metrics = await limiter.metrics()
    assert metrics.admitted == 3, f"baseline plus two authorised candidates: {metrics}"

    # The probe must reach the port it was authorized for. endpoint_port was
    # previously used only in the authorize() call, never in the URL, so a
    # non-default port authorised one service and probed another.
    limiter = RequestLimiter(3, 100.0, 10)
    client = FakeLimitedClient(limiter)
    plugin = VhostDiscoveryPlugin(
        ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"], "ports": [8443]})),
        candidates=["a.example.com"],
        limiter=limiter,
        client_factory=lambda: client,
        endpoint_scheme="https",
        endpoint_port=8443,
        request_interval=0,
    )
    discoveries = await plugin.execute("example.com")
    endpoint = discoveries[0].data["endpoint"]
    assert endpoint == "https://example.com:8443/", (
        f"the authorized port must appear in the probed endpoint, got {endpoint}"
    )

    # A default port stays out of the URL so recorded endpoints are canonical.
    for scheme, port in (("https", 443), ("http", 80)):
        plugin = VhostDiscoveryPlugin(
            ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"], "ports": [port]})),
            candidates=["a.example.com"],
            limiter=RequestLimiter(3, 100.0, 10),
            client_factory=lambda: FakeLimitedClient(RequestLimiter(3, 100.0, 10)),
            endpoint_scheme=scheme,
            endpoint_port=port,
            request_interval=0,
        )
        endpoint = (await plugin.execute("example.com"))[0].data["endpoint"]
        assert endpoint == f"{scheme}://example.com/", f"default port should be implicit, got {endpoint}"

    print("vhost request accounting test passed")


asyncio.run(main())
