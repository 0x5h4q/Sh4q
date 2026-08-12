
"""
sh4q/plugins/discovery.py

Discovery — what a plugin returns from execute(). Deliberately dumb: a
plugin describes what it observed in its own domain terms (kind + data),
with zero knowledge of Node, Relationship, or Storage.

IMPORTANT DISTINCTION, worth keeping permanently separate:
  Discovery           = "what did the plugin observe?"      (event payload)
  Node / Relationship = "what does Sh4q now believe?"        (normalized model)
A discovery handler converts one into the other. Plugins never do that
conversion themselves, and Discovery should never quietly grow into "a
Node with a different name" — if that temptation shows up later, it's a
sign the boundary is being eroded, not a sign Discovery needs new fields.
"""

from dataclasses import dataclass, field


@dataclass
class Discovery:
    kind: str            # e.g. "dns_resolution", "http_probe", "dns_error"
    data: dict = field(default_factory=dict)