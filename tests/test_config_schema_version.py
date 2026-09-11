from pathlib import Path

from sh4q.config import ConfigFileError, Sh4qConfig, load_config


def write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


root = Path("/tmp/sh4q_config_schema_test")
root.mkdir(parents=True, exist_ok=True)

versioned = root / "versioned.yaml"
write(versioned, "schema_version: 1\nscope:\n  targets: [example.com]\n")
config = load_config(versioned)
assert config.schema_version == 1
assert config.scope.targets == ["example.com"]

legacy = root / "legacy.yaml"
write(legacy, "scope:\n  targets: [example.com]\n")
assert load_config(legacy).schema_version == 1

unsupported = root / "unsupported.yaml"
write(unsupported, "schema_version: 2\n")
try:
    load_config(unsupported)
except ConfigFileError as error:
    assert "not supported" in str(error)
else:
    raise AssertionError("unsupported config schema should be rejected")

malformed = root / "malformed.yaml"
write(malformed, "schema_version: future\n")
try:
    load_config(malformed)
except ConfigFileError as error:
    assert "must be an integer" in str(error)
else:
    raise AssertionError("malformed config schema should be rejected")

non_mapping = root / "non-mapping.yaml"
write(non_mapping, "- example.com\n")
try:
    load_config(non_mapping)
except ConfigFileError as error:
    assert "YAML mapping" in str(error)
else:
    raise AssertionError("non-mapping config should be rejected")

assert Sh4qConfig().schema_version == 1
print("config schema version test passed")
