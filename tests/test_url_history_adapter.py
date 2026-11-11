"""Test the URL-history adapter: query CDX, apply bounds, report truncation."""

import asyncio

from sh4q.adapters.url_history import URLHistoryAdapter
from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine


config = Sh4qConfig(**{"scope": {"targets": ["example.com"]}})


def urls_for(hosts_and_counts, scheme_split=False):
    out = []
    for host, count in hosts_and_counts:
        for index in range(count):
            scheme = "https" if scheme_split and index % 10 == 0 else "http"
            out.append(f"{scheme}://{host}/page-{index:05d}")
    return "\n".join(out)


async def run_adapter(adapter, target, stdout_lines):
    """Feed stdout lines into the adapter by monkeypatching _query_cdx."""
    urls = [l.strip() for l in stdout_lines.splitlines() if l.strip()]
    
    async def fake_query_cdx(domain):
        return urls
    adapter._query_cdx = fake_query_cdx
    return await adapter.execute(target)


# --- every host is represented, not just the alphabetically early ones ----
adapter = URLHistoryAdapter(ScopeEngine(config), max_urls=100)
stdout = urls_for([
    ("aaa.example.com", 400),
    ("bbb.example.com", 400),
    ("zzz.example.com", 400),
])
discoveries = asyncio.run(run_adapter(adapter, "example.com", stdout))
batch = [d for d in discoveries if d.kind == "url_history_batch"][0]
selected = batch.data["urls"]
assert len(selected) == 100, len(selected)
hosts = {url.split("/")[2] for url in selected}
assert hosts == {"aaa.example.com", "bbb.example.com", "zzz.example.com"}, (
    f"a prefix of the alphabet would have kept only aaa: {sorted(hosts)}"
)

# --- and the scheme is not decided by sort order --------------------------
mixed = urls_for([("one.example.com", 500), ("two.example.com", 500)], scheme_split=True)
selected = None
adapter = URLHistoryAdapter(ScopeEngine(config), max_urls=120)
async def _run_mixed():
    return await run_adapter(adapter, "example.com", mixed)
results = asyncio.run(_run_mixed())
for d in results:
    if d.kind == "url_history_batch":
        selected = d.data["urls"]
https = [u for u in selected if u.startswith("https://")]
assert https, "every https URL was discarded by lexicographic truncation"

# --- under the bound, everything is kept and nothing is reordered away ----
small = urls_for([("one.example.com", 5), ("two.example.com", 5)])
everything = None
adapter = URLHistoryAdapter(ScopeEngine(config), max_urls=50)
async def _run_small():
    return await run_adapter(adapter, "example.com", small)
for d in asyncio.run(_run_small()):
    if d.kind == "url_history_batch":
        everything = d.data["urls"]
assert len(everything) == 10, everything
assert everything == sorted(everything), "the unbounded case stays sorted"

# --- deterministic: the same input always yields the same selection -------
stdout = urls_for([("aaa.example.com", 400), ("bbb.example.com", 400), ("zzz.example.com", 400)])
first = None
adapter = URLHistoryAdapter(ScopeEngine(config), max_urls=37)
async def _run_first():
    return await run_adapter(adapter, "example.com", stdout)
for d in asyncio.run(_run_first()):
    if d.kind == "url_history_batch":
        first = d.data["urls"]
second = None
async def _run_second():
    return await run_adapter(adapter, "example.com", stdout)
for d in asyncio.run(_run_second()):
    if d.kind == "url_history_batch":
        second = d.data["urls"]
assert first == second, "selection must not vary between runs"
assert first == sorted(first), "the kept set is presented in a stable order"

# --- truncation is still reported, with both numbers ----------------------
stdout = urls_for([("aaa.example.com", 400), ("bbb.example.com", 400), ("zzz.example.com", 400)])
adapter = URLHistoryAdapter(ScopeEngine(config), max_urls=100)
async def _run_trunc():
    return await run_adapter(adapter, "example.com", stdout)
results = asyncio.run(_run_trunc())
truncation = [d for d in results if d.kind == "url_history_truncated"]
assert len(truncation) == 1, [d.kind for d in results]
assert truncation[0].data["retained"] == 100
assert truncation[0].data["available"] == 1200, truncation[0].data

# --- the bound is configurable ------------------------------------------
config_big = Sh4qConfig(**{
    "scope": {"targets": ["example.com"]},
    "enrichment": {"max_historical_urls": 20000},
})
assert config_big.enrichment.max_historical_urls == 20000
assert config.enrichment.max_historical_urls == 5000, "the shipped default is unchanged"

print("url history adapter test passed")
