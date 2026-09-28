from pathlib import Path
import re
import tomllib


root = Path(__file__).resolve().parents[1]
readme = (root / "README.md").read_text(encoding="utf-8")
current_state = (root / "docs" / "current_state.md").read_text(encoding="utf-8")
roadmap = (root / "docs" / "v1_roadmap.md").read_text(encoding="utf-8")
version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]

assert not re.search(r"^(<<<<<<<|=======|>>>>>>>)", readme, re.MULTILINE)
assert f"releases/tag/v{version}" in readme
assert f"Sh4q `v{version}`" in readme
assert f"@v{version}" in readme
assert "docs/current_state.md" in readme
assert f"Published release: `v{version}`" in current_state
assert "Current Milestone: Workflow Foundations" in roadmap
assert "Scan templates" in roadmap

for relative in re.findall(r"\]\(([^)#]+)(?:#[^)]+)?\)", readme):
    if relative.startswith(("http://", "https://", "mailto:")):
        continue
    assert (root / relative).is_file(), f"README link does not exist: {relative}"

print("documentation QA test passed")

# The --profile help text must not overclaim. `full` deliberately excludes the
# experimental and active stages, and saying "all adapters" hid that.
from sh4q.cli.main import build_parser  # noqa: E402
import argparse  # noqa: E402

_subs = [a for a in build_parser()._actions if isinstance(a, argparse._SubParsersAction)][0]
_profile = next(
    a for a in _subs.choices["scan"]._actions if "--profile" in a.option_strings
)
assert "all current adapters" not in _profile.help, (
    "--profile full does not enable katana; do not describe it as all adapters"
)
for _stage in ("katana", "vhosts", "directories"):
    assert _stage in _profile.help, f"--profile help must say it excludes {_stage}"

print("profile help accuracy check passed")
