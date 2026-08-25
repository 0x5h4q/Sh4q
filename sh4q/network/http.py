from __future__ import annotations

import asyncio
import socket
from collections.abc import Awaitable, Callable
from urllib.parse import urljoin

import httpx

from sh4q.scope import ScopeEngine


class ScopedHTTPError(httpx.HTTPError):
    """Raised when an HTTP destination is outside the active policy."""


class _PinnedIPTransport(httpx.AsyncBaseTransport):
    """Connect to the policy-approved IP while preserving hostname identity."""

    def __init__(
        self,
        transport: httpx.AsyncBaseTransport | None = None,
        *,
        verify: bool | str = True,
    ):
        self._injected_transport = transport
        self._verify = verify
        self._transports: dict[tuple[str, str, int, str], httpx.AsyncHTTPTransport] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        pinned_ip = request.extensions.get("sh4q_pinned_ip")
        original_host = request.url.host
        if not isinstance(pinned_ip, str) or not original_host:
            raise ScopedHTTPError("request has no policy-approved destination address")

        extensions = dict(request.extensions)
        extensions.pop("sh4q_pinned_ip", None)
        extensions["sni_hostname"] = original_host
        pinned_request = httpx.Request(
            request.method,
            request.url.copy_with(host=pinned_ip),
            headers=request.headers,
            stream=request.stream,
            extensions=extensions,
        )
        if self._injected_transport is not None:
            transport = self._injected_transport
        else:
            port = request.url.port or (443 if request.url.scheme == "https" else 80)
            key = (request.url.scheme, original_host, port, pinned_ip)
            transport = self._transports.get(key)
            if transport is None:
                transport = httpx.AsyncHTTPTransport(verify=self._verify)
                self._transports[key] = transport
        return await transport.handle_async_request(pinned_request)

    async def aclose(self) -> None:
        if self._injected_transport is not None:
            await self._injected_transport.aclose()
        for transport in self._transports.values():
            await transport.aclose()


class ScopedHTTPClient:
    """HTTP client that validates every destination before it is contacted."""

    def __init__(
        self,
        scope: ScopeEngine,
        *,
        timeout: float,
        max_redirects: int = 10,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: Callable[[str, int], Awaitable[list[str]]] | None = None,
        verify: bool | str = True,
    ):
        self._scope = scope
        self._max_redirects = max(0, max_redirects)
        self._resolver = resolver or self._resolve
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            transport=_PinnedIPTransport(transport, verify=verify),
        )

    async def __aenter__(self) -> "ScopedHTTPClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._client.__aexit__(exc_type, exc, tb)

    async def get(self, url: str, **kwargs) -> httpx.Response:
        current = str(url)
        request_extensions = dict(kwargs.pop("extensions", {}))
        for _ in range(self._max_redirects + 1):
            pinned_ip = await self._authorize_url(current)
            extensions = dict(request_extensions)
            extensions["sh4q_pinned_ip"] = pinned_ip
            response = await self._client.get(current, extensions=extensions, **kwargs)
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response
            location = response.headers.get("location")
            if not location:
                return response
            current = urljoin(current, location)
        raise ScopedHTTPError(f"redirect limit exceeded for {url}")

    async def _authorize_url(self, url: str) -> str:
        parsed = httpx.URL(url)
        if parsed.scheme not in {"http", "https"} or not parsed.host:
            raise ScopedHTTPError(f"unsupported or invalid URL: {url}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        decision = self._scope.authorize(parsed.host, port)
        if not decision.allowed:
            raise ScopedHTTPError(f"HTTP destination denied: {decision.reason}")
        try:
            addresses = await self._resolver(parsed.host, port)
        except OSError as exc:
            raise ScopedHTTPError(f"could not resolve HTTP destination {parsed.host}: {exc}") from exc
        if not addresses:
            raise ScopedHTTPError(f"HTTP destination has no resolved address: {parsed.host}")
        for address in addresses:
            address_decision = self._scope.authorize_resolved_address(address)
            if not address_decision.allowed:
                raise ScopedHTTPError(f"HTTP destination denied: {address_decision.reason}")
        return addresses[0]

    @staticmethod
    async def _resolve(host: str, port: int) -> list[str]:
        loop = asyncio.get_running_loop()
        results = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return sorted({item[4][0] for item in results})
