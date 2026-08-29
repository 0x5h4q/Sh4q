from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception
import dns.resolver


class DNSResolutionError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class AsyncDNSResolver:
    """Resolve A and AAAA records with explicit DNS failure categories."""

    def __init__(self, *, lifetime: float = 4.0, resolver=None):
        self._resolver = resolver or dns.asyncresolver.Resolver()
        self._resolver.lifetime = max(0.1, lifetime)
        self._resolver.cache = dns.resolver.Cache()

    async def resolve_addresses(self, hostname: str) -> list[str]:
        results = await asyncio.gather(
            self._query(hostname, "A"),
            self._query(hostname, "AAAA"),
            return_exceptions=True,
        )
        addresses = sorted({
            address
            for result in results
            if isinstance(result, list)
            for address in result
        })
        if addresses:
            return addresses
        errors = [result for result in results if isinstance(result, DNSResolutionError)]
        if errors:
            priority = {"nxdomain": 0, "servfail": 1, "timeout": 2, "no_answer": 3, "dns_error": 4}
            raise sorted(errors, key=lambda error: priority.get(error.code, 99))[0]
        raise DNSResolutionError("no_answer", "no A or AAAA records returned")

    async def _query(self, hostname: str, record_type: str) -> list[str]:
        try:
            answer = await self._resolver.resolve(hostname, record_type)
            return [str(item) for item in answer]
        except dns.resolver.NXDOMAIN as error:
            raise DNSResolutionError("nxdomain", "domain does not exist") from error
        except dns.resolver.NoAnswer as error:
            raise DNSResolutionError("no_answer", f"no {record_type} answer") from error
        except dns.resolver.NoNameservers as error:
            raise DNSResolutionError("servfail", "no nameserver returned a usable answer") from error
        except dns.exception.Timeout as error:
            raise DNSResolutionError("timeout", f"{record_type} query timed out") from error
        except dns.exception.DNSException as error:
            raise DNSResolutionError("dns_error", str(error)) from error
