"""Certificate-transparency names must be resolvable.

CT runs by default and is often the largest source of subdomain names a
scan finds. Its output was dropped twice over: `discovered-dns` accepted
names only from Subfinder, and the discovered-host stages were only added
when `--sub` was passed. A real scan found 184 CT names and resolved none
of them, under any flag combination.

Resolving discovered names is a large traffic increase, so it stays
opt-in. What changed is that the opt-in is now reachable without
installing Subfinder, and that CT names count.
"""

import asyncio
import inspect

from sh4q.application.scan_runner import run_scan
from sh4q.cli.main import build_parser
from sh4q.plugins.discovered_dns_plugin import SUBDOMAIN_SOURCES, DiscoveredDNSPlugin
from sh4q.plugins.discovery import Discovery


def subdomain(hostname: str) -> Discovery:
    return Discovery(kind="subdomain_found", data={"hostname": hostname, "domain": "example.com"})


# --- discovered-dns accepts every subdomain-producing source --------------
assert "ct" in SUBDOMAIN_SOURCES, "certificate transparency produces subdomain names"
assert "subfinder" in SUBDOMAIN_SOURCES

plugin = DiscoveredDNSPlugin()
plugin.accept_discoveries([subdomain("from-ct.example.com")], "ct")
assert plugin._names == ["from-ct.example.com"], (
    f"CT names must be accepted for resolution, got {plugin._names}"
)

plugin = DiscoveredDNSPlugin()
plugin.accept_discoveries([subdomain("a.example.com")], "subfinder")
plugin.accept_discoveries([subdomain("b.example.com")], "ct")
assert plugin._names == ["a.example.com", "b.example.com"], plugin._names

# A stage that does not produce subdomain names is still ignored.
plugin = DiscoveredDNSPlugin()
plugin.accept_discoveries([subdomain("nope.example.com")], "directory-discovery")
plugin.accept_discoveries([subdomain("nope2.example.com")], None)
assert plugin._names == [], plugin._names

# The bound still applies, so a large CT result cannot become an unbounded sweep.
plugin = DiscoveredDNSPlugin(max_names=3)
plugin.accept_discoveries([subdomain(f"h{i}.example.com") for i in range(50)], "ct")
assert len(plugin._names) == 3, plugin._names


# --- the flag exists, and the default scan is unchanged -------------------
parser = build_parser()
assert parser.parse_args(["scan", "example.com"]).resolve is False, (
    "enrichment must stay opt-in: a default scan may not start resolving every CT name"
)
assert parser.parse_args(["scan", "example.com", "--resolve"]).resolve is True

assert "include_resolve" in inspect.signature(run_scan).parameters


# --- run_scan wires the stages for --resolve alone, without Subfinder -----
async def stages_for(**options) -> list[str]:
    """Build the chain and read it back. Gate 1 denies, so nothing is sent."""
    import tempfile
    from pathlib import Path

    root = Path(tempfile.mkdtemp(prefix="sh4q_sources_"))
    (root / "scope.yaml").write_text(
        f"schema_version: 1\nscope:\n  targets: []\noutput:\n  directory: {root / 'out'}\n",
        encoding="utf-8",
    )
    captured: list[str] = []
    import sh4q.application.scan_runner as runner

    real = runner.Scheduler

    class Recording(real):
        def __init__(self, plugins, *args, **kwargs):
            captured.extend(p.metadata.name for p in plugins)
            super().__init__(plugins, *args, **kwargs)

    runner.Scheduler = Recording
    try:
        await run_scan("denied.invalid", str(root / "scope.yaml"), **options)
    finally:
        runner.Scheduler = real
        import shutil

        shutil.rmtree(root, ignore_errors=True)
    return captured


async def main() -> None:
    default = await stages_for()
    assert "discovered-dns" not in default, (
        f"a default scan must not enrich; stages were {default}"
    )
    assert "ct" in default, default

    resolved = await stages_for(include_resolve=True)
    assert "discovered-dns" in resolved, resolved
    assert "discovered-http" in resolved, resolved
    assert "subfinder" not in resolved, (
        "--resolve must not require Subfinder; that coupling was the defect"
    )

    print("discovered name sources test passed")


asyncio.run(main())
