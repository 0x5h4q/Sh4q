from pathlib import Path
import re
import tomllib


root = Path(__file__).resolve().parents[1]
readme = (root / "README.md").read_text(encoding="utf-8")
current_state = (root / "docs" / "current_state.md").read_text(encoding="utf-8")
roadmap = (root / "docs" / "v1_roadmap.md").read_text(encoding="utf-8")
installation = (root / "docs" / "installation.md").read_text(encoding="utf-8")
version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]

assert not re.search(r"^(<<<<<<<|=======|>>>>>>>)", readme, re.MULTILINE)
assert f"releases/tag/v{version}" in readme
assert f"Sh4q `v{version}`" in readme
assert "docs/current_state.md" in readme

# The README badge names a test count, and a badge is read as current by
# definition. It has gone stale twice in one week -- at 88 and at 99 -- and
# with no remote CI to regenerate it, this assertion is the only thing that
# can notice. Keep the number; make it impossible to forget.
import sys  # noqa: E402

sys.path.insert(0, str(root / "tools"))
from run_offline_tests import OFFLINE_TESTS  # noqa: E402

badge = re.search(r"offline%20suite-(\d+)%20checks", readme)
assert badge, "the README must carry the offline-suite badge"
assert int(badge.group(1)) == len(OFFLINE_TESTS), (
    f"the README badge says {badge.group(1)} checks; the runner has "
    f"{len(OFFLINE_TESTS)}. Update the badge, or it claims a number nobody "
    "verified."
)
assert f'alt="{len(OFFLINE_TESTS)} offline checks"' in readme, (
    "the badge alt text must match the badge"
)

# The recommended install must name a moving reference, not a tag.
#
# A tag is a snapshot of the day it was cut. v1.3.0 was three days old and
# already 34 merges behind `main`, two of them scope-authorization fixes, while
# both README and installation.md still told a new user to install the tag.
#
# Note what the check below could not catch: the pinned version *equalled* the
# package version, so nothing was stale by its measure. The gap was between the
# tag and `main`, which no assertion here can see. Hence this one, which pins
# the posture instead.
for document, text in (("README.md", readme), ("docs/installation.md", installation)):
    assert "Sh4q.git@main" in text, (
        f"{document} must recommend installing from @main; a tag hands a new "
        "user whatever was true on the day it was cut"
    )
assert "which-reference-to-install" in readme, (
    "the README must link to the explanation of what a tag does not include"
)
assert f"Published release: `v{version}`" in current_state
assert "Current Milestone: Workflow Foundations" in roadmap
assert "Scan templates" in roadmap

# An install instruction pinning an old tag hands users the previous release.
# This was missed once: README was checked, docs/installation.md was not, and
# v1.3.0 shipped telling people to install v1.2.0.
install_pin = re.compile(r"(?:Sh4q(?:\.git)?@|releases/tag/)v(\d+\.\d+\.\d+)")
for document in sorted(root.glob("docs/**/*.md")) + [root / "README.md", root / "RELEASING.md"]:
    if document.parent.name == "historical":
        continue
    for pinned in set(install_pin.findall(document.read_text(encoding="utf-8"))):
        assert pinned == version, (
            f"{document.relative_to(root)} pins v{pinned}, but the package is {version}. "
            "Every install instruction and release link must name the current release."
        )

# Every stage status `sh4q show` can print must be explained somewhere. The
# table is the durable account of what a scan did, and `truncated` arrived
# with nothing telling an operator it is not a failure.
_scheduler = (root / "sh4q" / "scheduler.py").read_text(encoding="utf-8")
_reference = (root / "docs" / "operator_reference.md").read_text(encoding="utf-8")
_statuses = set(re.findall(r'"status": "([a-z_]+)"', _scheduler)) | {"completed"}
_undocumented = sorted(s for s in _statuses if f"`{s}`" not in _reference)
assert not _undocumented, (
    f"stage status(es) {_undocumented} are printed by `show` and explained "
    "nowhere; document them in docs/operator_reference.md"
)

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
