
"""
sh4q/events/event.py

The Event Interface's data shape — one of the six frozen contracts.
Deliberately minimal: a type (what kind of thing happened) and a payload
(the actual data), plus a timestamp for free provenance.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Event:
    type: str            # e.g. "dns_found", "http_probed"
    payload: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=_now)