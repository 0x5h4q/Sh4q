

from pathlib import Path
from typing import Any

from pydantic import ValidationError
import yaml

from .schema import CURRENT_CONFIG_SCHEMA_VERSION, Sh4qConfig


class ConfigFileError(ValueError):
    pass


def _validate_schema_version(raw: dict[str, Any], path: Path) -> None:
    version = raw.get("schema_version", CURRENT_CONFIG_SCHEMA_VERSION)
    if isinstance(version, bool) or not isinstance(version, int):
        raise ConfigFileError(
            f"config schema_version must be an integer in {path}: {version!r}"
        )
    if version != CURRENT_CONFIG_SCHEMA_VERSION:
        raise ConfigFileError(
            f"config schema version {version} in {path} is not supported; "
            f"supported version: {CURRENT_CONFIG_SCHEMA_VERSION}"
        )


def load_config(path: str | Path) -> Sh4qConfig:
    path = Path(path)
    if not path.exists():
        raise ConfigFileError(f"config file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as config_file:
            raw = yaml.safe_load(config_file)
    except (OSError, yaml.YAMLError) as error:
        raise ConfigFileError(f"unable to read config file {path}: {error}") from error

    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigFileError(f"config file must contain a YAML mapping: {path}")

    _validate_schema_version(raw, path)

    try:
        return Sh4qConfig(**raw)
    except ValidationError as error:
        raise ConfigFileError(f"invalid config file {path}: {error}") from error
