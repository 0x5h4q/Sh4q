from pathlib import Path

from sh4q.config import load_template
from sh4q.cli.main import build_parser


root = Path("/tmp/sh4q_template_test")
root.mkdir(parents=True, exist_ok=True)
(root / "scope.yaml").write_text("schema_version: 1\nscope:\n  targets: [example.com]\n", encoding="utf-8")
(root / "template.yaml").write_text(
    "schema_version: 1\nname: passive\nconfig: scope.yaml\nstages: [sub, js]\n",
    encoding="utf-8",
)
template = load_template(root / "template.yaml")
assert template.name == "passive"
assert template.stages == ("sub", "js")
assert template.config == (root / "scope.yaml").resolve()
args = build_parser().parse_args(["scan", "example.com", "--template", str(root / "template.yaml")])
assert args.template == str(root / "template.yaml")

(root / "bad.yaml").write_text("schema_version: 1\nname: bad\nstages: [unknown]\n", encoding="utf-8")
try:
    load_template(root / "bad.yaml")
except ValueError as error:
    assert "unknown scan template stage" in str(error)
else:
    raise AssertionError("unknown stages should be rejected")

print("scan template test passed")
