from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .schema import CURRENT_CONFIG_SCHEMA_VERSION


TEMPLATE_STAGES = {
    "sub": "sub",
    "httpx": "httpx",
    "amass": "amass",
    "url-history": "url_history",
    "js": "js",
    "js-bundles": "js_bundles",
    "katana": "katana",
    "vhosts": "vhosts",
    "directories": "directories",
}


@dataclass(frozen=True)
class ScanTemplate:
    name: str
    config: Path | None
    stages: tuple[str, ...]
    vhosts_file: str | None = None
    directories_file: str | None = None


def load_template(path: str | Path) -> ScanTemplate:
    template_path = Path(path).expanduser()
    if not template_path.is_file():
        raise ValueError(f"scan template not found: {template_path}")
    try:
        raw: Any = yaml.safe_load(template_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ValueError(f"unable to read scan template {template_path}: {error}") from error
    if not isinstance(raw, dict):
        raise ValueError(f"scan template must contain a YAML mapping: {template_path}")
    version = raw.get("schema_version", CURRENT_CONFIG_SCHEMA_VERSION)
    if isinstance(version, bool) or not isinstance(version, int) or version != CURRENT_CONFIG_SCHEMA_VERSION:
        raise ValueError(
            f"scan template schema version {version!r} is unsupported; "
            f"supported version: {CURRENT_CONFIG_SCHEMA_VERSION}"
        )
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("scan template name must be a non-empty string")
    stages = raw.get("stages", [])
    if not isinstance(stages, list) or any(not isinstance(stage, str) for stage in stages):
        raise ValueError("scan template stages must be a list of strings")
    unknown = sorted(set(stages) - set(TEMPLATE_STAGES))
    if unknown:
        raise ValueError(f"unknown scan template stage(s): {', '.join(unknown)}")
    if len(set(stages)) != len(stages):
        raise ValueError("scan template stages must not contain duplicates")
    config = raw.get("config")
    config_path = None
    if config is not None:
        if not isinstance(config, str) or not config.strip():
            raise ValueError("scan template config must be a non-empty path")
        config_path = (template_path.parent / config).resolve()
        if not config_path.is_file():
            raise ValueError(f"scan template config not found: {config_path}")
    return ScanTemplate(
        name=name.strip(),
        config=config_path,
        stages=tuple(stages),
        vhosts_file=raw.get("vhosts_file"),
        directories_file=raw.get("directories_file"),
    )
