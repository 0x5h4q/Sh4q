"""Every config shipped with Sh4q must be safe to copy.

sh4q/config/example_com.yaml listed 0.0.0.0/0 alongside a domain, so the
example that operators were most likely to copy authorized every address
on the internet. A scope-enforcement tool must not ship an example that
disables scope.
"""

import ipaddress
from pathlib import Path

from sh4q.config import load_config
from sh4q.scope import ScopeEngine


ROOT = Path(__file__).resolve().parents[1]
# A lab config is allowed to be permissive; it is named so an operator knows.
LAB_CONFIGS = {"default.yaml"}
# Anything broader than this in one entry is a supernet, not a scope.
MAX_HOSTS = 1024

configs = sorted(ROOT.glob("config/*.yaml")) + sorted(ROOT.glob("sh4q/config/*.yaml"))
assert configs, "no packaged configs found; has the layout changed?"

checked = 0
for path in configs:
    text = path.read_text(encoding="utf-8")
    if "stages:" in text and "name:" in text and "scope:" not in text:
        continue  # a scan template, not a scope file
    config = load_config(path)
    checked += 1
    is_lab = path.name in LAB_CONFIGS

    for target in config.scope.targets:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            continue  # a hostname, bounded by its own name
        assert network.num_addresses <= MAX_HOSTS, (
            f"{path.name} authorizes {target}, which covers {network.num_addresses} "
            "addresses. A packaged example must not authorize a supernet."
        )
        assert not network.num_addresses > MAX_HOSTS

    if not is_lab:
        assert config.scope.allow_private_addresses is False, (
            f"{path.name} enables allow_private_addresses. Only a config named as a "
            "lab may do that, so an operator can tell from the filename."
        )
        # A non-lab example must actually deny something, or it teaches nothing.
        scope = ScopeEngine(config)
        assert not scope.authorize("definitely-not-in-scope.invalid").allowed, (
            f"{path.name} authorizes an unrelated host"
        )
        assert not scope.authorize_resolved_address("127.0.0.1").allowed, (
            f"{path.name} would permit a loopback address"
        )

assert checked >= 2, f"expected to check at least two scope files, checked {checked}"

# The retired config must not come back.
assert not (ROOT / "sh4q" / "config" / "example_com.yaml").exists(), (
    "example_com.yaml authorized 0.0.0.0/0 and was removed; do not restore it"
)

print(f"packaged configs test passed ({checked} scope files checked)")
