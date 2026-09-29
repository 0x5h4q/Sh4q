from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .schema import CURRENT_CONFIG_SCHEMA_VERSION


TEMPLATE_STAGES = {
    "sub": "sub",
    "resolve": "resolve",
    "httpx": "httpx",
    "url-history": "url_history",
    "js": "js",
    "js-bundles": "js_bundles",
    "katana": "katana",
    "vhosts": "vhosts",
    "directories": "directories",
}


# Options a template already decides. Supplying any of them alongside
# --template is a conflict, not an override: the template is the single
# source of truth for stage selection and configuration.
TEMPLATE_OWNED_OPTIONS = (
    ("--config", "config"),
    ("--profile", "profile"),
    ("--sub", "sub"),
    ("--resolve", "resolve"),
    ("--httpx", "httpx"),
    ("--url-history", "url_history"),
    ("--js", "js"),
    ("--js-bundles", "js_bundles"),
    ("--katana", "katana"),
    ("--vhosts", "vhosts"),
    ("--vhosts-file", "vhosts_file"),
    ("--vhosts-from-scan", "vhosts_from_scan"),
    ("--directories", "directories"),
    ("--directories-file", "directories_file"),
)


def conflicting_template_options(args) -> list[str]:
    """Return the option names a template would otherwise silently overwrite."""
    return [flag for flag, attribute in TEMPLATE_OWNED_OPTIONS if getattr(args, attribute, None)]


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
    vhosts_file = _optional_path_field(raw, "vhosts_file", template_path)
    directories_file = _optional_path_field(raw, "directories_file", template_path)
    if vhosts_file and "vhosts" not in stages:
        raise ValueError("scan template sets vhosts_file but does not select the 'vhosts' stage")
    if directories_file and "directories" not in stages:
        raise ValueError(
            "scan template sets directories_file but does not select the 'directories' stage"
        )
    if "directories" in stages and not directories_file:
        raise ValueError(
            "scan template selects the 'directories' stage but sets no directories_file; "
            "directory discovery always requires an explicit candidate file"
        )
    return ScanTemplate(
        name=name.strip(),
        config=config_path,
        stages=tuple(stages),
        vhosts_file=vhosts_file,
        directories_file=directories_file,
    )


def _optional_path_field(raw: dict, field: str, template_path: Path) -> str | None:
    """Validate an optional path-valued template field.

    Resolved relative to the template, exactly like ``config``. A template is
    meant to be a portable recipe, so its candidate files must not depend on
    the directory the operator happens to run from. Absolute paths are left
    as given.
    """
    value = raw.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"scan template {field} must be a non-empty path")
    resolved = (template_path.parent / value.strip()).resolve()
    if not resolved.is_file():
        raise ValueError(f"scan template {field} not found: {resolved}")
    return str(resolved)
