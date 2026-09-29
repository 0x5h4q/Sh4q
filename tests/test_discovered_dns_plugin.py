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
    # Names are normalised and the bound is respected. Which names are chosen
    # when there are more than the bound is a sampling decision covered by
    # test_name_selection.py; here the contract is normalisation, the bound,
    # and which sources are accepted at all.
    assert plugin._names == ["api.example.com", "example.com"], plugin._names
    assert all(n == n.lower() and not n.endswith(".") for n in plugin._names)

    plugin.accept_discoveries([
        Discovery("subdomain_found", {"hostname": "portal.example.com"}),
        Discovery("subdomain_found", {"hostname": "API.EXAMPLE.COM."}),
    ], "subfinder")
    assert len(plugin._names) == 2, plugin._names
    assert plugin._names == sorted(set(plugin._names)), "no duplicates, stable order"

    before = list(plugin._names)
    plugin.accept_discoveries([], "subfinder")
    assert plugin._names == before, "an empty batch must change nothing"

    plugin.accept_discoveries([
        Discovery("subdomain_found", {"hostname": "other.test"}),
    ], "unrelated")
    assert plugin._names == before, "a source that does not produce subdomains is ignored"
    assert not any(n.endswith(".test") for n in plugin._names)
    subfinder_only = DiscoveredDNSPlugin(max_names=2)
    subfinder_only.accept_discoveries([
        Discovery("subdomain_found", {"hostname": "portal.example.com"}),
    ], "subfinder")
    assert subfinder_only._names == ["portal.example.com"]
    # Resolve a known pair so the outcome does not depend on which names the
    # sampler chose above.
    plugin._sources = {}
    plugin._admit(["example.com", "api.example.com"], source="ct")
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
