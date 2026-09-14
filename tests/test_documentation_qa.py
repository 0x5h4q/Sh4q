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
