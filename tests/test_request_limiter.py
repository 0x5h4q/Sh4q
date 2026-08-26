import asyncio
import time

import httpx

from sh4q.config import Sh4qConfig
from sh4q.network import RequestLimiter, ScopedHTTPClient, ScopedHTTPError
from sh4q.scope import ScopeEngine


async def main() -> None:
    limiter = RequestLimiter(max_concurrent=2, requests_per_second=1000, budget=4)
    active = peak = contacts = 0

    async def worker() -> None:
        nonlocal active, peak, contacts
        permit = await limiter.acquire()
        assert permit is not None
        async with permit:
            contacts += 1
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.02)
            active -= 1
            permit.succeeded()

    await asyncio.gather(*(worker() for _ in range(4)))
    metrics = await limiter.metrics()
    assert contacts == 4
    assert peak == metrics.peak_concurrency == 2
    assert metrics.admitted == metrics.completed == 4
    assert metrics.failed == metrics.denied == metrics.active == 0

    paced = RequestLimiter(max_concurrent=3, requests_per_second=20, budget=3)
    starts = []
    for _ in range(3):
        permit = await paced.acquire()
        assert permit is not None
        async with permit:
            starts.append(time.monotonic())
            permit.succeeded()
    assert starts[1] - starts[0] >= 0.04
    assert starts[2] - starts[1] >= 0.04

    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["allowed.test"], "ports": [80]}}))
    budgeted = RequestLimiter(max_concurrent=1, requests_per_second=1000, budget=1)
    contacted = []

    async def handler(request: httpx.Request) -> httpx.Response:
        contacted.append(str(request.url))
        raise httpx.ConnectError("first address failed", request=request)

    async def resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34", "93.184.216.35"]

    async with ScopedHTTPClient(
        scope,
        timeout=1,
        transport=httpx.MockTransport(handler),
        resolver=resolve,
        limiter=budgeted,
    ) as client:
        try:
            await client.get("http://allowed.test/")
        except ScopedHTTPError as error:
            assert error.phase == "limit"
        else:
            raise AssertionError("fallback request bypassed the request budget")
    assert len(contacted) == 1
    metrics = await budgeted.metrics()
    assert metrics.admitted == 1 and metrics.denied == 1 and metrics.failed == 1

    denied = RequestLimiter(max_concurrent=1, requests_per_second=1000, budget=1)
    async with ScopedHTTPClient(
        scope,
        timeout=1,
        transport=httpx.MockTransport(handler),
        resolver=resolve,
        limiter=denied,
    ) as client:
        try:
            await client.get("http://blocked.test/")
        except ScopedHTTPError:
            pass
    metrics = await denied.metrics()
    assert metrics.admitted == metrics.denied == 0
    print("request limiter tests passed")


asyncio.run(main())
