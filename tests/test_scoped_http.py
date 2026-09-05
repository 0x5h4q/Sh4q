import asyncio

import httpx

from sh4q.config import Sh4qConfig
from sh4q.network import ScopedHTTPClient, ScopedHTTPError
from sh4q.network import RequestLimiter
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

    class BodyStream(httpx.AsyncByteStream):
        def __init__(self, chunks: list[bytes]):
            self.chunks = chunks
            self.yielded = 0

        async def __aiter__(self):
            for chunk in self.chunks:
                self.yielded += 1
                yield chunk

        async def aclose(self) -> None:
            return None

    streams: list[BodyStream] = []

    async def bounded_handler(request: httpx.Request) -> httpx.Response:
        stream = BodyStream([b"1234", b"5678", b"never-read"])
        streams.append(stream)
        return httpx.Response(200, headers={"content-type": "text/plain"}, stream=stream, request=request)

    bounded_limiter = RequestLimiter(1, 1000, 2)
    async with ScopedHTTPClient(
        scope, timeout=1, transport=httpx.MockTransport(bounded_handler), resolver=resolve,
        limiter=bounded_limiter,
    ) as client:
        response, body, truncated = await client.get_text_bounded("http://allowed.test/", 5)
        assert response.status_code == 200
        assert body == "12345"
        assert truncated is True
        assert streams[-1].yielded == 2
        response, body, truncated = await client.get_text_bounded("http://allowed.test/", 5)
        assert body == "12345"
        assert truncated is True
    metrics = await bounded_limiter.metrics()
    assert metrics.admitted == 2
    assert metrics.completed == 2
    assert metrics.failed == 0

    async def exact_handler(request: httpx.Request) -> httpx.Response:
        stream = BodyStream([b"12345"])
        return httpx.Response(200, stream=stream, request=request)

    async with ScopedHTTPClient(
        scope, timeout=1, transport=httpx.MockTransport(exact_handler), resolver=resolve
    ) as client:
        _, body, truncated = await client.get_text_bounded("http://allowed.test/", 5)
        assert body == "12345"
        assert truncated is False

    declared_stream = BodyStream([b"should-not-be-read"])

    async def declared_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-length": "999"},
            stream=declared_stream,
            request=request,
        )

    async with ScopedHTTPClient(
        scope, timeout=1, transport=httpx.MockTransport(declared_handler), resolver=resolve
    ) as client:
        _, body, truncated = await client.get_text_bounded("http://allowed.test/", 5)
        assert body == ""
        assert truncated is True
    assert declared_stream.yielded == 0

    async def redirect_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://blocked.test/secret"}, request=request)

    async with ScopedHTTPClient(
        scope, timeout=1, transport=httpx.MockTransport(redirect_handler), resolver=resolve
    ) as client:
        try:
            await client.get_text_bounded("http://allowed.test/", 100)
        except ScopedHTTPError:
            pass
        else:
            raise AssertionError("out-of-scope bounded redirect was not blocked")
    print("scoped HTTP redirect test passed")


asyncio.run(main())
