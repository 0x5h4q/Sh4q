import subprocess
import sys
from pathlib import Path

from sh4q.config import conflicting_template_options, load_template
from sh4q.cli.main import build_parser


root = Path("/tmp/sh4q_template_test")
root.mkdir(parents=True, exist_ok=True)
(root / "scope.yaml").write_text("schema_version: 1\nscope:\n  targets: [example.com]\n", encoding="utf-8")
(root / "paths.txt").write_text("admin\n", encoding="utf-8")


def write(name: str, body: str) -> Path:
    path = root / name
    path.write_text(body, encoding="utf-8")
    return path


def rejects(name: str, body: str, fragment: str) -> None:
    """A malformed template must be refused with an explanatory message."""
    try:
        load_template(write(name, body))
    except ValueError as error:
        assert fragment in str(error), f"{name}: expected {fragment!r}, got {str(error)!r}"
    else:
        raise AssertionError(f"{name}: should have been rejected")


def cli_rejects(argv: list[str], fragment: str) -> None:
    """The CLI exits 2 and explains the conflict on stderr. No scan starts."""
    completed = subprocess.run(
        [sys.executable, "-m", "sh4q", *argv],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2, f"{argv}: expected exit 2, got {completed.returncode}"
    assert fragment in completed.stderr, f"{argv}: expected {fragment!r}, got {completed.stderr!r}"


# --- a well-formed template loads and resolves its config relative to itself ---
template_path = write(
    "template.yaml",
    "schema_version: 1\nname: passive\nconfig: scope.yaml\nstages: [sub, js]\n",
)
template = load_template(template_path)
assert template.name == "passive"
assert template.stages == ("sub", "js")
assert template.config == (root / "scope.yaml").resolve()
assert template.vhosts_file is None
assert template.directories_file is None

args = build_parser().parse_args(["scan", "example.com", "--template", str(template_path)])
assert args.template == str(template_path)

# --- stage list validation ---
rejects("bad.yaml", "schema_version: 1\nname: bad\nstages: [unknown]\n", "unknown scan template stage")
rejects("dupe.yaml", "schema_version: 1\nname: dupe\nstages: [sub, sub]\n", "must not contain duplicates")
rejects("noname.yaml", "schema_version: 1\nstages: [sub]\n", "name must be a non-empty string")
rejects("badver.yaml", "schema_version: 99\nname: v\nstages: [sub]\n", "unsupported")
rejects("notmap.yaml", "- just\n- a\n- list\n", "must contain a YAML mapping")

# --- optional path fields are typed, not passed through raw ---
rejects(
    "listfile.yaml",
    "schema_version: 1\nname: t\nstages: [vhosts]\nvhosts_file: [a, b]\n",
    "vhosts_file must be a non-empty path",
)
rejects(
    "emptyfile.yaml",
    "schema_version: 1\nname: t\nstages: [vhosts]\nvhosts_file: '   '\n",
    "vhosts_file must be a non-empty path",
)

# --- a path field without its stage, and the directories stage without its file ---
(root / "hosts.txt").write_text("a.example.com\n", encoding="utf-8")
rejects(
    "orphanvhost.yaml",
    "schema_version: 1\nname: t\nstages: [sub]\nvhosts_file: hosts.txt\n",
    "does not select the 'vhosts' stage",
)
# A candidate file is resolved against the template, not the working directory,
# and a missing one is refused at load time rather than mid-scan.
rejects(
    "missingvhost.yaml",
    "schema_version: 1\nname: t\nstages: [vhosts]\nvhosts_file: nowhere.txt\n",
    "vhosts_file not found",
)
rejects(
    "orphandirs.yaml",
    "schema_version: 1\nname: t\nstages: [sub]\ndirectories_file: paths.txt\n",
    "does not select the 'directories' stage",
)
rejects(
    "dirsnofile.yaml",
    "schema_version: 1\nname: t\nstages: [directories]\n",
    "sets no directories_file",
)

# --- a directory template that is complete loads, and reaches argparse intact ---
complete = write(
    "complete.yaml",
    "schema_version: 1\nname: dirs\nstages: [directories]\ndirectories_file: paths.txt\n",
)
loaded = load_template(complete)
assert loaded.directories_file == str((root / "paths.txt").resolve()), (
    "a candidate file must resolve against the template so the recipe is portable"
)
assert loaded.stages == ("directories",)

# Running from an unrelated working directory must not change resolution.
import os  # noqa: E402

_previous = os.getcwd()
os.chdir("/")
try:
    assert load_template(complete).directories_file == str((root / "paths.txt").resolve())
finally:
    os.chdir(_previous)

# --- the template owns stage selection: conflicts are detected, not overwritten ---
# Every template-owned option is covered, checked against the parser's own
# destinations so a renamed flag cannot silently drop out of the conflict set.
parser = build_parser()
for flag, attribute in [
    ("--config", "config"), ("--profile", "profile"), ("--sub", "sub"),
    ("--httpx", "httpx"), ("--url-history", "url_history"),
    ("--js", "js"), ("--js-bundles", "js_bundles"), ("--katana", "katana"),
    ("--vhosts", "vhosts"), ("--vhosts-file", "vhosts_file"),
    ("--vhosts-from-scan", "vhosts_from_scan"), ("--directories", "directories"),
    ("--directories-file", "directories_file"),
]:
    value = [] if attribute in {"sub", "httpx", "url_history", "js", "js_bundles",
                                "katana", "vhosts", "directories"} else ["web" if flag == "--profile" else "x"]
    parsed = parser.parse_args(["scan", "example.com", "--template", str(template_path), flag, *value])
    assert getattr(parsed, attribute), f"{flag} did not set {attribute}"
    assert conflicting_template_options(parsed) == [flag], (
        f"{flag} was not reported as conflicting with --template"
    )

# a template on its own conflicts with nothing
clean = parser.parse_args(["scan", "example.com", "--template", str(template_path)])
assert conflicting_template_options(clean) == []

# end to end: the process exits 2 before any scan work begins
cli_rejects(
    ["scan", "example.com", "--template", str(template_path), "--sub"],
    "--template cannot be combined with --sub",
)
cli_rejects(
    ["scan", "example.com", "--template", str(root / "dirsnofile.yaml")],
    "sets no directories_file",
)

print("scan template test passed")
