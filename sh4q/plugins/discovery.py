

from dataclasses import dataclass, field


@dataclass
class Discovery:
    kind: str   # e.g. "dns_resolution", "http_probe", "dns_error" and all thatt
    data: dict = field(default_factory=dict)