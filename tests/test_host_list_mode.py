"""An operator-supplied host list is resolved and probed like a discovery.

Sh4q could only enrich names it discovered itself. Checking a list you
already have -- from a prior scan, a client's inventory, a certificate
dump -- meant leaving the tool. During an authorised engagement, 131
names had to be resolved with dig because there was no way to hand them
to sh4q.

The list enters the same path as a discovered name: authorised at Gate 2
before contact, deduplicated, bounded, and drawing on the same budget.
"""

import asyncio
import shutil
import tempfile
from pathlib import Path

from sh4q.application.scan_runner import run_scan
from sh4q.cli.main import build_parser
from sh4q.config import Sh4qConfig
from sh4q.plugins.discovered_dns_plugin import (
    DiscoveredDNSPlugin,
    load_host_names,
    normalize_host,
)
from sh4q.scope import ScopeEngine


ROOT = Path(tempfile.mkdtemp(prefix="sh4q_hostlist_"))

# --- normalisation: operators paste all of these ---------------------------
assert normalize_host("host.example.com") == "host.example.com"
assert normalize_host("HOST.Example.com.") == "host.example.com", "case and trailing dot"
assert normalize_host("https://host.example.com/path?q=1") == "host.example.com", "a URL"
assert normalize_host("host.example.com:8443") == "host.example.com", "a host:port pair"
assert normalize_host("http://user@host.example.com") == "host.example.com", "userinfo"
assert normalize_host("[2606:4700::1]") == "2606:4700::1", "a bracketed IPv6 literal"
for junk in ("", "   ", "# comment", "not a hostname at all", "//x", "with\tcontrol"):
    assert normalize_host(junk) is None, junk


# --- loading: bounded, deduplicated, comments skipped ----------------------
(ROOT / "hosts.txt").write_text(
    "# candidates from a prior scan\n"
    "a.example.com\n"
    "A.EXAMPLE.COM.\n"                       # duplicate after normalisation
    "https://b.example.com/x\n"
    "\n"
    "   # indented comment\n"
    "evil.test\n"                            # out of scope, still loaded
    "not a hostname\n",
    encoding="utf-8",
)
loaded = load_host_names(ROOT / "hosts.txt")
assert loaded.accepted == ("a.example.com", "b.example.com", "evil.test"), loaded.accepted
assert loaded.duplicates == 1, loaded.duplicates
assert [reason for _, _, reason in loaded.rejected] == ["not a hostname"], loaded.rejected

# The bound is enforced rather than silently truncating.
(ROOT / "toomany.txt").write_text("\n".join(f"h{i}.example.com" for i in range(12)), encoding="utf-8")
try:
    load_host_names(ROOT / "toomany.txt", max_hosts=10)
except ValueError as error:
    assert "exceeds the maximum" in str(error), error
else:
    raise AssertionError("an oversized host list must be refused")

try:
    load_host_names(ROOT / "absent.txt")
except ValueError as error:
    assert "host list not found" in str(error), error
else:
    raise AssertionError("a missing host list must be refused")


# --- scope is applied before anything is contacted -------------------------
scope = ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"], "excluded": ["bad.example.com"]}))
plugin = DiscoveredDNSPlugin(scope=scope, names=loaded.accepted)
assert plugin._names == ["a.example.com", "b.example.com"], (
    f"an out-of-scope name must never be queued for contact: {plugin._names}"
)

# A supplied name and a discovered name share one deduplicated, bounded set.
from sh4q.plugins.discovery import Discovery  # noqa: E402

plugin.accept_discoveries(
    [Discovery(kind="subdomain_found", data={"hostname": "c.example.com", "domain": "example.com"})],
    "ct",
)
assert plugin._names == ["a.example.com", "b.example.com", "c.example.com"], plugin._names
plugin.accept_discoveries(
    [Discovery(kind="subdomain_found", data={"hostname": "A.Example.com", "domain": "example.com"})],
    "ct",
)
assert plugin._names.count("a.example.com") == 1, "a rediscovered name must not duplicate"

bounded = DiscoveredDNSPlugin(max_names=2, names=[f"h{i}.example.com" for i in range(9)])
assert len(bounded._names) == 2, bounded._names


# --- the CLI flag and the runner wiring ------------------------------------
args = build_parser().parse_args(["scan", "example.com", "--hosts-file", str(ROOT / "hosts.txt")])
assert args.hosts_file == str(ROOT / "hosts.txt")
assert build_parser().parse_args(["scan", "example.com"]).hosts_file is None


async def stages_for(**options) -> list[str]:
    """Build the chain against a scope that denies at Gate 1: nothing is sent."""
    (ROOT / "scope.yaml").write_text(
        f"schema_version: 1\nscope:\n  targets: []\noutput:\n  directory: {ROOT / 'out'}\n",
        encoding="utf-8",
    )
    captured: list[str] = []
    import sh4q.application.scan_runner as runner

    real = runner.Scheduler

    class Recording(real):
        def __init__(self, plugins, *a, **kw):
            captured.extend(p.metadata.name for p in plugins)
            super().__init__(plugins, *a, **kw)

    runner.Scheduler = Recording
    try:
        await run_scan("denied.invalid", str(ROOT / "scope.yaml"), **options)
    finally:
        runner.Scheduler = real
    return captured


async def main() -> None:
    # A host list alone enables enrichment; neither --sub nor --resolve needed.
    stages = await stages_for(hosts_file=str(ROOT / "hosts.txt"))
    assert "discovered-dns" in stages, stages
    assert "discovered-http" in stages, stages
    assert "subfinder" not in stages, "a host list must not require Subfinder"

    # Without one, the default scan is unchanged.
    assert "discovered-dns" not in await stages_for(), "a default scan must not enrich"

    # A bad list fails before any database or network work.
    from sh4q.adapters import AdapterExecutionError

    try:
        await stages_for(hosts_file=str(ROOT / "absent.txt"))
    except AdapterExecutionError as error:
        assert "host list not found" in str(error), error
    else:
        raise AssertionError("a missing host list must stop the scan")

    print("host list mode test passed")


asyncio.run(main())
shutil.rmtree(ROOT, ignore_errors=True)
