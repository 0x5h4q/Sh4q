"""Which historical URLs are kept when there are more than the bound.

`sorted(urls)[:max_urls]` is a prefix of the alphabet, not a sample. On a
real scan it kept 5000 of 14658 and the consequences were systematic
rather than proportional:

  - 91% of the kept set was a single host
  - only 20 distinct hosts appeared at all
  - every one of the 30 https URLs was discarded, because "http://"
    sorts before "https://" and the cut landed inside the http block

This is the name-selection bias in a second place: taking the
alphabetically first N spent 62% of a 500-name budget on hostnames
beginning with "c". The remedy is the same -- spread across the range,
deterministically -- and so is the rule: when there are more candidates
than the bound, which ones get chosen is a correctness concern.

The bound is also configurable now. 5000 was fixed while the enrichment
bounds became adjustable, so an operator could raise the names they
resolve but not the history they keep.
"""

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
adapter = URLHistoryAdapter(ScopeEngine(config), max_urls=120)
async def _run_mixed():
    return await run_adapter(adapter, "example.com", mixed)
discoveries = asyncio.run(_run_mixed())
batch = [d for d in discoveries if d.kind == "url_history_batch"][0]
https = [u for u in batch.data["urls"] if u.startswith("https://")]
assert https, "every https URL was discarded by lexicographic truncation"

# --- under the bound, everything is kept and nothing is reordered away ----
small = urls_for([("one.example.com", 5), ("two.example.com", 5)])
adapter = URLHistoryAdapter(ScopeEngine(config), max_urls=50)
async def _run_small():
    return await run_adapter(adapter, "example.com", small)
discoveries = asyncio.run(_run_small())
batch = [d for d in discoveries if d.kind == "url_history_batch"][0]
everything = batch.data["urls"]
assert len(everything) == 10, everything
assert everything == sorted(everything), "the unbounded case stays sorted"

# --- deterministic: the same input always yields the same selection -------
stdout = urls_for([("aaa.example.com", 400), ("bbb.example.com", 400), ("zzz.example.com", 400)])
adapter = URLHistoryAdapter(ScopeEngine(config), max_urls=37)
async def _run_first():
    return await run_adapter(adapter, "example.com", stdout)
discoveries = asyncio.run(_run_first())
first = [d for d in discoveries if d.kind == "url_history_batch"][0].data["urls"]
async def _run_second():
    return await run_adapter(adapter, "example.com", stdout)
discoveries = asyncio.run(_run_second())
second = [d for d in discoveries if d.kind == "url_history_batch"][0].data["urls"]
assert first == second, "selection must not vary between runs"
assert first == sorted(first), "the kept set is presented in a stable order"

# --- truncation is still reported, with both numbers ----------------------
stdout = urls_for([("aaa.example.com", 400), ("bbb.example.com", 400), ("zzz.example.com", 400)])
adapter = URLHistoryAdapter(ScopeEngine(config), max_urls=100)
async def _run_trunc():
    return await run_adapter(adapter, "example.com", stdout)
discoveries = asyncio.run(_run_trunc())
truncation = [d for d in discoveries if d.kind == "url_history_truncated"]
assert len(truncation) == 1, [d.kind for d in discoveries]
assert truncation[0].data["retained"] == 100
assert truncation[0].data["available"] == 1200, truncation[0].data

# --- the bound is configurable ------------------------------------------
config_big = Sh4qConfig(**{
    "scope": {"targets": ["example.com"]},
    "enrichment": {"max_historical_urls": 20000},
})
assert config_big.enrichment.max_historical_urls == 20000
assert config.enrichment.max_historical_urls == 5000, "the shipped default is unchanged"

print("url history selection test passed")
