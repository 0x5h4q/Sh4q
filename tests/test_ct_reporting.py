import asyncio
import contextlib
import io

from sh4q.plugins.ct_connectors import CTConnector, CTConnectorError
from sh4q.plugins.ct_plugin import CTPlugin


class SuccessfulConnector(CTConnector):
    name = "certspotter"

    def __init__(self):
        self.calls = 0

    async def fetch_hostnames(self, target: str, timeout: float) -> list[str]:
        self.calls += 1
        return [f"www.{target}", f"portal.{target}"]


class DegradedConnector(CTConnector):
    name = "crt.sh"

    async def fetch_hostnames(self, target: str, timeout: float) -> list[str]:
        raise CTConnectorError("HTTP 404", retryable=False)


class FlakyConnector(CTConnector):
    name = "flaky"

    def __init__(self):
        self.calls = 0

    async def fetch_hostnames(self, target: str, timeout: float) -> list[str]:
        self.calls += 1
        if self.calls == 1:
            raise CTConnectorError("HTTP 502", retryable=True)
        return [f"api.{target}"]


async def main() -> None:
    plugin = CTPlugin(connectors=[SuccessfulConnector(), DegradedConnector()])
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        discoveries = await plugin.execute("example.com")

    rendered = output.getvalue()
    assert "CT providers:" in rendered
    assert "certspotter    success      2 names" in rendered
    assert "crt.sh         degraded     0 names retained; HTTP 404" in rendered
    assert "SAVED:" not in rendered

    statuses = {
        item.data["source"]: item.data
        for item in discoveries
        if item.kind == "ct_provider_status"
    }
    assert statuses["certspotter"]["status"] == "success"
    assert statuses["certspotter"]["names"] == 2
    assert statuses["crt.sh"]["status"] == "degraded"
    assert statuses["crt.sh"]["error"] == "HTTP 404"
    assert sum(item.kind == "subdomain_found" for item in discoveries) == 2

    successful = SuccessfulConnector()
    flaky = FlakyConnector()
    retrying = CTPlugin(connectors=[successful, flaky])
    first = await retrying.execute("example.com")
    assert any(item.data.get("retryable") is True for item in first)
    second = await retrying.execute("example.com")
    assert successful.calls == 1
    assert flaky.calls == 2
    assert sum(item.kind == "subdomain_found" for item in second) == 3
    assert any(
        item.kind == "ct_provider_status"
        and item.data["source"] == "certspotter"
        and item.data["preserved"] is True
        for item in second
    )

    class LimitedConnector(CTConnector):
        name = "limited"

        def __init__(self):
            self.calls = 0

        async def fetch_hostnames(self, target: str, timeout: float) -> list[str]:
            self.calls += 1
            raise CTConnectorError(
                "Retry-After: 60s",
                retryable=False,
                rate_limited=True,
                partial_hostnames={f"limited.{target}"},
            )

    limited = LimitedConnector()
    limited_plugin = CTPlugin(connectors=[limited])
    limited_output = io.StringIO()
    with contextlib.redirect_stdout(limited_output):
        limited_first = await limited_plugin.execute("example.com")
    await limited_plugin.execute("example.com")
    assert limited.calls == 1
    assert "rate-limited 1 names retained" in limited_output.getvalue()
    limited_status = next(item for item in limited_first if item.kind == "ct_provider_status")
    assert limited_status.data["status"] == "partial_rate_limited"
    assert limited_status.data["names"] == 1
    print("CT provider reporting test passed")


asyncio.run(main())
