

from pathlib import Path
import yaml

from .schema import Sh4qConfig


def load_config(path: str | Path) -> Sh4qConfig:
   
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with path.open("r") as f:
        raw = yaml.safe_load(f) or {}

    # pydantic does the actual validation work here . This single line is what rejects a malformed config before it ever reaches the Scope Engine.
    return Sh4qConfig(**raw)