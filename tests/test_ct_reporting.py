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
    retry_output = io.StringIO()
    with contextlib.redirect_stdout(retry_output):
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

    # The durable discovery recorded `preserved: True` above, and this file
    # asserted that -- but never the printed table, so a `continue` dropped the
    # preserved provider from terminal output and nothing failed. On a real
    # target crt.sh timed out three times while certspotter's 184 names sat
    # preserved and unmentioned, and attempts 2 and 3 printed only
    # "crt.sh degraded 0 names retained", reading as total collapse.
    retried = retry_output.getvalue()
    assert "certspotter" in retried, (
        f"a provider whose result was carried over must still be listed: {retried!r}"
    )
    assert "certspotter    success      2 names (preserved)" in retried, retried
    assert "flaky          success      1 names" in retried, retried
    assert "(preserved)" not in retried.split("flaky")[1].splitlines()[0], (
        "a provider that was re-fetched this attempt is not preserved"
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
    limited_retry = io.StringIO()
    with contextlib.redirect_stdout(limited_retry):
        await limited_plugin.execute("example.com")
    assert limited.calls == 1
    assert "rate-limited 1 names retained" in limited_output.getvalue()
    # A rate-limited provider is terminal: it is not re-queried, and it must
    # still appear on the next attempt rather than vanishing from the table.
    assert "rate-limited 1 names retained" in limited_retry.getvalue(), limited_retry.getvalue()
    assert "(preserved)" in limited_retry.getvalue(), limited_retry.getvalue()
    limited_status = next(item for item in limited_first if item.kind == "ct_provider_status")
    assert limited_status.data["status"] == "partial_rate_limited"
    assert limited_status.data["names"] == 1
    # --- a provider that said no is not asked again -----------------------
    # crt.name answers only for a registrable apex. Given a subdomain it
    # returns HTTP 400 "invalid apex", which is terminal -- retryable=False.
    # But only rate-limited errors were cached as terminal, so a stage retry
    # driven by a *different* provider re-queried it: on a real scan it was
    # asked three times and refused three times, three wasted requests to a
    # service that had already given its final answer.
    class TerminalConnector(CTConnector):
        name = "terminal"

        def __init__(self):
            self.calls = 0

        async def fetch_hostnames(self, target, timeout):
            self.calls += 1
            raise CTConnectorError(
                "terminal returned HTTP 400: invalid apex", retryable=False
            )

    class RetryableConnector(CTConnector):
        """Keeps failing retryably, so the stage keeps retrying."""

        name = "retryable"

        def __init__(self):
            self.calls = 0

        async def fetch_hostnames(self, target, timeout):
            self.calls += 1
            raise CTConnectorError("retryable returned HTTP 502", retryable=True)

    terminal, retryable = TerminalConnector(), RetryableConnector()
    mixed = CTPlugin(connectors=[terminal, retryable])
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        for _ in range(3):
            await mixed.execute("example.com")
    assert terminal.calls == 1, (
        f"a terminal error must be asked once, was asked {terminal.calls} times"
    )
    assert retryable.calls == 3, (
        f"a retryable error must be re-attempted, got {retryable.calls}"
    )
    # And it stays visible in the table rather than disappearing once cached.
    rendered = output.getvalue()
    assert rendered.count("terminal") >= 3, rendered
    assert "(preserved)" in rendered, rendered

    print("CT provider reporting test passed")


asyncio.run(main())
