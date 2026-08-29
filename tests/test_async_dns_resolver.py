import asyncio

import dns.exception
import dns.resolver

from sh4q.network import AsyncDNSResolver, DNSResolutionError


class FakeResolver:
    def __init__(self, answers):
        self.answers = answers
        self.lifetime = None
        self.cache = None

    async def resolve(self, hostname, record_type):
        result = self.answers[record_type]
        if isinstance(result, Exception):
            raise result
        return result


async def main():
    partial = AsyncDNSResolver(resolver=FakeResolver({
        "A": ["93.184.216.34"],
        "AAAA": dns.resolver.NoAnswer(),
    }))
    assert await partial.resolve_addresses("example.com") == ["93.184.216.34"]

    missing = AsyncDNSResolver(resolver=FakeResolver({
        "A": dns.resolver.NXDOMAIN(),
        "AAAA": dns.resolver.NXDOMAIN(),
    }))
    try:
        await missing.resolve_addresses("missing.example.com")
    except DNSResolutionError as error:
        assert error.code == "nxdomain"
    else:
        raise AssertionError("NXDOMAIN was not classified")

    timed = AsyncDNSResolver(resolver=FakeResolver({
        "A": dns.exception.Timeout(),
        "AAAA": dns.exception.Timeout(),
    }))
    try:
        await timed.resolve_addresses("slow.example.com")
    except DNSResolutionError as error:
        assert error.code == "timeout"
    else:
        raise AssertionError("DNS timeout was not classified")
    print("async DNS resolver test passed")


asyncio.run(main())
