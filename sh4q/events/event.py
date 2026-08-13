from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Event:
    type: str           
    payload: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=_now)
    id: str = field(default_factory=lambda: uuid4().hex)   # stable id for durable tracking