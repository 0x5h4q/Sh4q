import asyncio

from sh4q.plugins.discovered_dns_plugin import DiscoveredDNSPlugin
from sh4q.plugins import Discovery


async def main():
    active = peak = 0

    async def resolve(name):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        if name == "example.com":
            return []
        return ["93.184.216.34"]

    plugin = DiscoveredDNSPlugin(max_names=2, max_concurrent=1, resolver=resolve)
    plugin.accept_discoveries([
        Discovery("subdomain_found", {"hostname": "Example.COM."}),
        Discovery("subdomain_found", {"hostname": "api.example.com"}),
        Discovery("subdomain_found", {"hostname": "ignored.example.com"}),
    ], "subfinder")
    assert plugin._names == ["api.example.com", "example.com"]
    results = await plugin.execute("example.com")
    assert [item.kind for item in results] == [
        "discovered_dns_resolution",
        "discovered_dns_error",
    ]
    assert peak == 1
    async def slow(name):
        await asyncio.sleep(1)
        return ["93.184.216.34"]
    timed = DiscoveredDNSPlugin(max_names=1, resolver=slow, per_name_timeout=0.01)
    timed.accept_discoveries([Discovery("subdomain_found", {"hostname": "api.example.com"})], "subfinder")
    timeout_results = await timed.execute("example.com")
    assert timeout_results[0].data["error"] == "resolution timed out"
    print("discovered DNS plugin test passed")


asyncio.run(main())
