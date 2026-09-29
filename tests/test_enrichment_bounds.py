"""How much of what a scan finds it goes on to check must be adjustable.

A real scan of a large estate used 316 of its 900 request budget while
leaving 711 discovered names unexamined. Raising the budget would have
changed nothing: the limit that bit was the number of names resolved,
and that was hardcoded at 500 with no way to ask for more.
"""

import asyncio
import shutil
import tempfile
from pathlib import Path

from sh4q.application.scan_runner import run_scan
from sh4q.config import Sh4qConfig


# --- the bounds exist, default unchanged, and are validated ---------------
default = Sh4qConfig()
assert default.enrichment.max_names_resolved == 500, "the default must not shift silently"
assert default.enrichment.max_hosts_probed == 200

raised = Sh4qConfig(enrichment={"max_names_resolved": 1500, "max_hosts_probed": 600})
assert raised.enrichment.max_names_resolved == 1500
assert raised.enrichment.max_hosts_probed == 600

for bad in ({"max_names_resolved": 0}, {"max_names_resolved": 99999}, {"max_hosts_probed": -1}):
    try:
        Sh4qConfig(enrichment=bad)
    except Exception:
        pass
    else:
        raise AssertionError(f"{bad} should be rejected: a bound with no ceiling is not a bound")

# A configuration written before this existed still loads.
assert Sh4qConfig(**{"scope": {"targets": ["example.com"]}}).enrichment.max_names_resolved == 500


# --- the configured values reach the stages -------------------------------
ROOT = Path(tempfile.mkdtemp(prefix="sh4q_bounds_"))


async def bounds_for(resolved: int, probed: int) -> tuple[int, int]:
    (ROOT / "scope.yaml").write_text(
        "schema_version: 1\n"
        "scope:\n  targets: []\n"
        f"enrichment:\n  max_names_resolved: {resolved}\n  max_hosts_probed: {probed}\n"
        f"output:\n  directory: {ROOT / 'out'}\n",
        encoding="utf-8",
    )
    seen: dict[str, int] = {}
    import sh4q.application.scan_runner as runner

    real = runner.Scheduler

    class Recording(real):
        def __init__(self, plugins, *a, **kw):
            for plugin in plugins:
                if plugin.metadata.name == "discovered-dns":
                    seen["resolve"] = plugin._max_names
                if plugin.metadata.name == "discovered-http":
                    seen["probe"] = plugin._max_names
            super().__init__(plugins, *a, **kw)

    runner.Scheduler = Recording
    try:
        await run_scan("denied.invalid", str(ROOT / "scope.yaml"), include_resolve=True)
    finally:
        runner.Scheduler = real
    return seen.get("resolve", -1), seen.get("probe", -1)


async def main() -> None:
    assert await bounds_for(1500, 600) == (1500, 600), "configured bounds must reach the stages"
    assert await bounds_for(10, 5) == (10, 5), "lowering them must work too"
    shutil.rmtree(ROOT, ignore_errors=True)
    print("enrichment bounds test passed")


asyncio.run(main())
