import asyncio
import contextlib
import io

from sh4q.plugins.ct_connectors import CTConnector, CTConnectorError
from sh4q.plugins.ct_plugin import CTPlugin


class SuccessfulConnector(CTConnector):
    name = "certspotter"

    async def fetch_hostnames(self, target: str, timeout: float) -> list[str]:
        return [f"www.{target}", f"portal.{target}"]


class DegradedConnector(CTConnector):
    name = "crt.sh"

    async def fetch_hostnames(self, target: str, timeout: float) -> list[str]:
        raise CTConnectorError("HTTP 404", retryable=False)


async def main() -> None:
    plugin = CTPlugin(connectors=[SuccessfulConnector(), DegradedConnector()])
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        discoveries = await plugin.execute("example.com")

    rendered = output.getvalue()
    assert "CT providers:" in rendered
    assert "certspotter    success      2 names" in rendered
    assert "crt.sh         degraded     HTTP 404" in rendered
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
    print("CT provider reporting test passed")


asyncio.run(main())
