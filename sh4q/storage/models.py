


from dataclasses import dataclass, field
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Node:
    type: str          
    value: str          
    attributes: dict = field(default_factory=dict)
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)

    @property
    def id(self) -> str:
        return f"{self.type}:{self.value}"


@dataclass
class Relationship:
    from_id: str
    to_id: str
    type: str           
    attributes: dict = field(default_factory=dict)
    created_at: str = field(default_factory=_now)

    @property
    def id(self) -> str:
        return f"{self.from_id}:{self.type}:{self.to_id}"