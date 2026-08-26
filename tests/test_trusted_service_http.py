import asyncio

import httpx

from sh4q.network import ScopedHTTPError, TrustedServiceHTTPClient


async def main() -> None:
    seen: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, request=request)

    async def resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    async with TrustedServiceHTTPClient(
        {"api.example.test"},
        timeout=1,
        transport=httpx.MockTransport(handler),
        resolver=resolve,
    ) as client:
        response = await client.get("https://api.example.test/v1")
        assert response.status_code == 200
        try:
            await client.get("https://evil.example.test/")
        except ScopedHTTPError as error:
            assert "unapproved" in str(error)
        else:
            raise AssertionError("unapproved service host was contacted")
    assert seen == ["https://93.184.216.34/v1"]

    async def redirect_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example.test/"}, request=request)

    async with TrustedServiceHTTPClient(
        {"api.example.test"},
        timeout=1,
        transport=httpx.MockTransport(redirect_handler),
        resolver=resolve,
    ) as client:
        try:
            await client.get("https://api.example.test/v1")
        except ScopedHTTPError as error:
            assert "redirect denied" in str(error)
        else:
            raise AssertionError("trusted-service redirect was followed")

    attempts: list[str] = []

    async def fallback_handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request.url.host)
        if request.url.host == "93.184.216.34":
            raise httpx.ConnectError("unreachable", request=request)
        return httpx.Response(200, request=request)

    async def resolve_multiple(host: str, port: int) -> list[str]:
        return ["93.184.216.34", "93.184.216.35"]

    async with TrustedServiceHTTPClient(
        {"api.example.test"},
        timeout=1,
        transport=httpx.MockTransport(fallback_handler),
        resolver=resolve_multiple,
    ) as client:
        response = await client.get("https://api.example.test/v1")
        assert response.status_code == 200
    assert attempts == ["93.184.216.34", "93.184.216.35"]
    print("trusted service HTTP test passed")


asyncio.run(main())
