
"""
sh4q/config/loader.py

Turns a YAML file into a validated Sh4qConfig object. This is intentionally
tiny — the loader's only job is "read file -> hand to pydantic -> return
typed object, or raise a clear error." No logic beyond that belongs here.
"""

from pathlib import Path
import yaml

from .schema import Sh4qConfig


def load_config(path: str | Path) -> Sh4qConfig:
    """
    Load and validate a YAML config file.

    Raises FileNotFoundError if the path doesn't exist, and
    pydantic.ValidationError if the file's contents don't match the schema
    (e.g. rate_limit.max_concurrent set to a negative number).
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with path.open("r") as f:
        raw = yaml.safe_load(f) or {}

    # pydantic does the actual validation work here — this single line is
    # what rejects a malformed config before it ever reaches the Scope Engine.
    return Sh4qConfig(**raw)