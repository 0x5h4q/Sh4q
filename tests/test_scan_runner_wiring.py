"""run_scan must assemble a valid plugin chain for every stage combination.

The offline suite tested plugins individually but never the `if include_x:`
chain that builds them. A refactor once left an orphaned plugins.append()
inside the wrong branch, so every --directories scan raised
UnboundLocalError before contacting anything. Nothing failed but the
operator's terminal.

This walks the real wiring with network-free stages and asserts the chain
builds and orders correctly.
"""

import asyncio
import shutil
import tempfile
from pathlib import Path

from sh4q.application.scan_runner import run_scan
from sh4q.scheduler import Scheduler


ROOT = Path(tempfile.mkdtemp(prefix="sh4q_wiring_"))
(ROOT / "paths.txt").write_text("admin\n", encoding="utf-8")
(ROOT / "vhosts.txt").write_text("admin.example.test\n", encoding="utf-8")
(ROOT / "scope.yaml").write_text(
    # An empty target list denies at Gate 1, so no stage ever runs and no
    # packet is sent -- but the whole chain is built first, which is the point.
    "schema_version: 1\n"
    "scope:\n"
    "  targets: []\n"
    f"output:\n  directory: {ROOT / 'out'}\n",
    encoding="utf-8",
)

STAGE_COMBINATIONS = [
    {},
    {"include_javascript": True},
    {"include_javascript": True, "include_javascript_bundles": True},
    {"include_vhosts": True, "vhosts_file": str(ROOT / "vhosts.txt")},
    {"include_directories": True, "directories_file": str(ROOT / "paths.txt")},
    {
        "include_vhosts": True,
        "vhosts_file": str(ROOT / "vhosts.txt"),
        "include_directories": True,
        "directories_file": str(ROOT / "paths.txt"),
        "include_javascript": True,
        "include_javascript_bundles": True,
    },
]

# Adapter stages need their executable present; include them only when it is.
if shutil.which("subfinder"):
    STAGE_COMBINATIONS.append({"include_subfinder": True})
if shutil.which("waybackurls"):
    STAGE_COMBINATIONS.append({"include_url_history": True})


async def main() -> None:
    for options in STAGE_COMBINATIONS:
        label = ", ".join(sorted(k for k, v in options.items() if v is True)) or "native only"
        summary = await run_scan("denied.invalid", str(ROOT / "scope.yaml"), **options)
        # Gate 1 denies, so the run is a no-op -- but reaching this line proves
        # every plugin in the combination was constructed without raising.
        assert summary.scope_allowed is False, label
        assert summary.discoveries == 0, label

    # The chain a full local scan builds must also order without a cycle or an
    # unmet dependency, which the scheduler resolves rather than run_scan.
    from sh4q.config import Sh4qConfig
    from sh4q.scope import ScopeEngine
    from sh4q.plugins.dns_plugin import DNSPlugin
    from sh4q.plugins.http_plugin import HTTPPlugin
    from sh4q.plugins import DirectoryDiscoveryPlugin, VhostDiscoveryPlugin

    scope = ScopeEngine(Sh4qConfig(scope={"targets": ["example.test"]}))
    scheduler = Scheduler(
        plugins=[
            DirectoryDiscoveryPlugin(scope, ROOT / "paths.txt"),
            VhostDiscoveryPlugin(scope, ROOT / "vhosts.txt"),
            HTTPPlugin(scope),
            DNSPlugin(),
        ],
        scope=scope,
        bus=None,
    )
    ordered = [plugin.metadata.name for plugin in scheduler._ordered_plugins()]
    assert ordered.index("dns") < ordered.index("http"), ordered
    assert ordered.index("http") < ordered.index("vhost-discovery"), ordered
    assert ordered.index("http") < ordered.index("directory-discovery"), ordered

    print("scan runner wiring test passed")


asyncio.run(main())
