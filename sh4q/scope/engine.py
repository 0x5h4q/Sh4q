
"""


The Scope Engine — the "Scope Interface" from your six frozen contracts.
This is the bouncer at the door: every target, before ANY network call,
gets checked here first. No plugin, no matter what it's doing, is allowed
to skip this.

Design choice: authorize() returns a ScopeDecision (allowed + reason),
not a plain bool. Every decision needs to be explainable and loggable —
"why was this denied?" should never require re-deriving the logic by hand.
"""

import ipaddress
from dataclasses import dataclass

from sh4q.config import Sh4qConfig


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str

    def __bool__(self) -> bool:
        # lets you write `if decision:` naturally, while still keeping
        # the reason available for logging
        return self.allowed


class ScopeEngine:
    """
    Given a loaded Sh4qConfig, decides whether a specific target (and
    optionally port) is allowed to be touched during this scan.
    """

    def __init__(self, config: Sh4qConfig):
        self._targets = config.scope.targets
        self._excluded = config.scope.excluded
        self._ports = set(config.scope.ports)
        self._budget = config.rate_limit.budget
        self._requests_used = 0

    def authorize(self, target: str, port: int | None = None) -> ScopeDecision:
        # 1. Budget — a hard cap on total requests, regardless of target validity
        if self._requests_used >= self._budget:
            return ScopeDecision(False, f"request budget exhausted ({self._budget})")

        # 2. Excluded list always wins, even over an otherwise-valid match
        if self._matches_any(target, self._excluded):
            return ScopeDecision(False, f"{target} is explicitly excluded")

        # 3. Must match something in the allowed target list
        if not self._matches_any(target, self._targets):
            return ScopeDecision(False, f"{target} is not in the allowed target list")

        # 4. Port check, only if a port was actually specified
        if port is not None and self._ports and port not in self._ports:
            return ScopeDecision(False, f"port {port} is not in the allowed port list")

        self._requests_used += 1
        return ScopeDecision(True, "authorized")

    def _matches_any(self, target: str, patterns: list[str]) -> bool:
        return any(self._matches_one(target, pattern) for pattern in patterns)

    def _matches_one(self, target: str, pattern: str) -> bool:
        # Try CIDR/IP matching first (e.g. pattern "10.0.0.0/24", target "10.0.0.5")
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            ip = ipaddress.ip_address(target)
            return ip in network
        except ValueError:
            pass  # target or pattern isn't IP-shaped — fall through to hostname logic

        # Exact hostname match
        if target == pattern:
            return True

        # Subdomain inheritance: "sub.example.com" is in scope if
        # "example.com" is an allowed target
        if target.endswith("." + pattern):
            return True

        return False
