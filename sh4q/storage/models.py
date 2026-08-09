
"""
sh4q/storage/models.py

Node and Relationship — the two concepts the Storage Interface deals in,
matching the graph-shaped Normalization Schema rather than flat "assets."

Deliberate design choice: id is a PROPERTY, derived deterministically from
content (type + value for Node, from/type/to for Relationship), not a
random UUID. This means discovering "example.com" twice — even from two
different plugins — naturally lands on the same node instead of creating
a duplicate. That's what lets the Asset Store enrich/merge over time
instead of accumulating copies. This is the dedup mechanism, for free,
just from how IDs are chosen.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Node:
    type: str          # "domain" | "ip" | "host" | "service" | "url" | "certificate" | "technology" | "finding" | ...
    value: str          # the actual value, e.g. "example.com" or "10.0.0.5"
    attributes: dict = field(default_factory=dict)
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)

    @property
    def id(self) -> str:
        # Deterministic — same type+value always produces the same id,
        # which is exactly what makes re-discovery a merge, not a duplicate.
        return f"{self.type}:{self.value}"


@dataclass
class Relationship:
    from_id: str
    to_id: str
    type: str           # "RESOLVES_TO" | "HOSTS" | "RUNS" | "SERVES" | ...
    attributes: dict = field(default_factory=dict)
    created_at: str = field(default_factory=_now)

    @property
    def id(self) -> str:
        return f"{self.from_id}:{self.type}:{self.to_id}"