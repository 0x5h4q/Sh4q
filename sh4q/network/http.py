from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from urllib.parse import urljoin

import httpx

from sh4q.scope import ScopeEngine
from sh4q.network.limits import RequestLimiter


class ScopedHTTPError(httpx.HTTPError):
    """Raised when an HTTP destination is outside the active policy."""

    def __init__(self, message: str, *, phase: str = "policy", address: str | None = None):
        super().__init__(message)
        self.phase = phase
        self.address = address


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
        limiter: RequestLimiter | None = None,
    ):
        self._scope = scope
        self._limiter = limiter
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
            addresses = await self._authorize_url(current)
            response = None
            last_error = None
            for pinned_ip in addresses:
                extensions = dict(request_extensions)
                extensions["sh4q_pinned_ip"] = pinned_ip
                try:
                    response = await self._limited_get(current, extensions=extensions, **kwargs)
                    break
                except httpx.ConnectTimeout as exc:
                    last_error = ScopedHTTPError(str(exc) or "connection timed out", phase="connect", address=pinned_ip)
                except httpx.ConnectError as exc:
                    last_error = ScopedHTTPError(str(exc) or "connection failed", phase="connect", address=pinned_ip)
                except httpx.ReadTimeout as exc:
                    last_error = ScopedHTTPError(str(exc) or "response timed out", phase="read", address=pinned_ip)
            if response is None:
                raise last_error or ScopedHTTPError("HTTP request failed")
            response.extensions["sh4q_pinned_ip"] = pinned_ip
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response
            location = response.headers.get("location")
            if not location:
                return response
            current = urljoin(current, location)
        raise ScopedHTTPError(f"redirect limit exceeded for {url}")

    async def _limited_get(self, url: str, **kwargs) -> httpx.Response:
        if self._limiter is None:
            return await self._client.get(url, **kwargs)
        permit = await self._limiter.acquire()
        if permit is None:
            raise ScopedHTTPError("request budget exhausted", phase="limit")
        async with permit:
            response = await self._client.get(url, **kwargs)
            permit.succeeded()
            return response

    async def _authorize_url(self, url: str) -> list[str]:
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
        return addresses

    @staticmethod
    async def _resolve(host: str, port: int) -> list[str]:
        loop = asyncio.get_running_loop()
        results = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return sorted({item[4][0] for item in results})


class TrustedServiceHTTPClient:
    """Pinned HTTPS client for explicitly approved third-party service APIs."""

    def __init__(
        self,
        allowed_hosts: set[str],
        *,
        timeout: float,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: Callable[[str, int], Awaitable[list[str]]] | None = None,
        limiter: RequestLimiter | None = None,
    ):
        self._allowed_hosts = {host.lower().rstrip(".") for host in allowed_hosts}
        self._resolver = resolver or ScopedHTTPClient._resolve
        self._limiter = limiter
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            transport=_PinnedIPTransport(transport),
        )

    async def __aenter__(self) -> "TrustedServiceHTTPClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._client.__aexit__(exc_type, exc, tb)

    async def get(self, url: str, **kwargs) -> httpx.Response:
        parsed = httpx.URL(url)
        if parsed.scheme != "https" or not parsed.host or parsed.port not in (None, 443):
            raise ScopedHTTPError("trusted service requires HTTPS on port 443")
        host = parsed.host.lower().rstrip(".")
        if host not in self._allowed_hosts:
            raise ScopedHTTPError(f"unapproved trusted service host: {host}")
        addresses = await self._resolver(host, 443)
        if not addresses:
            raise ScopedHTTPError(f"trusted service has no resolved address: {host}")
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                raise ScopedHTTPError(f"trusted service resolves to non-public address: {address}")
        response = None
        last_error = None
        for address in addresses:
            try:
                response = await self._limited_get(
                    url, extensions={"sh4q_pinned_ip": address}, **kwargs
                )
                break
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
                last_error = exc
        if response is None:
            raise last_error or ScopedHTTPError("trusted service request failed")
        if response.is_redirect:
            raise ScopedHTTPError(f"trusted service redirect denied: {url}")
        return response

    async def _limited_get(self, url: str, **kwargs) -> httpx.Response:
        if self._limiter is None:
            return await self._client.get(url, **kwargs)
        permit = await self._limiter.acquire()
        if permit is None:
            raise ScopedHTTPError("request budget exhausted", phase="limit")
        async with permit:
            response = await self._client.get(url, **kwargs)
            permit.succeeded()
            return response
