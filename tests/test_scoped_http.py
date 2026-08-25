import asyncio

import httpx

from sh4q.config import Sh4qConfig
from sh4q.network import ScopedHTTPClient, ScopedHTTPError
from sh4q.scope import ScopeEngine


async def main() -> None:
    scope = ScopeEngine(Sh4qConfig(**{"scope": {"targets": ["allowed.test"], "ports": [80]}}))
    requests: list[tuple[str, str, bytes | None]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(
            (
                str(request.url),
                request.headers["host"],
                request.extensions.get("sni_hostname"),
            )
        )
        return httpx.Response(302, headers={"location": "http://blocked.test/secret"}, request=request)

    transport = httpx.MockTransport(handler)
    async def resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    async with ScopedHTTPClient(scope, timeout=1, transport=transport, resolver=resolve) as client:
        try:
            await client.get("http://allowed.test/")
        except ScopedHTTPError:
            pass
        else:
            raise AssertionError("out-of-scope redirect was not blocked")

    assert requests == [("http://93.184.216.34/", "allowed.test", "allowed.test")]
    assert scope.authorize("ALLOWED.TEST.").allowed

    async def reserved_resolve(host: str, port: int) -> list[str]:
        return ["127.0.0.1"]

    async with ScopedHTTPClient(scope, timeout=1, transport=transport, resolver=reserved_resolve) as client:
        try:
            await client.get("http://allowed.test/")
        except ScopedHTTPError as error:
            assert "reserved or non-public" in str(error)
        else:
            raise AssertionError("reserved destination was not blocked")
    assert len(requests) == 1

    async def mixed_resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34", "127.0.0.1"]

    async with ScopedHTTPClient(scope, timeout=1, transport=transport, resolver=mixed_resolve) as client:
        try:
            await client.get("http://allowed.test/")
        except ScopedHTTPError:
            pass
        else:
            raise AssertionError("mixed public/private DNS answer was not blocked")
    assert len(requests) == 1

    idna_scope = ScopeEngine(
        Sh4qConfig(**{"scope": {"targets": ["xn--bcher-kva.example"]}})
    )
    assert idna_scope.authorize("BÜCHER.EXAMPLE.").allowed
    print("scoped HTTP redirect test passed")


asyncio.run(main())
