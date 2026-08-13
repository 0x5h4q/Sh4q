

import ipaddress
from dataclasses import dataclass

from sh4q.config import Sh4qConfig


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str

    def __bool__(self) -> bool:
        return self.allowed


class ScopeEngine:

    def __init__(self, config: Sh4qConfig):
        self._targets = config.scope.targets
        self._excluded = config.scope.excluded
        self._ports = set(config.scope.ports)
        self._budget = config.rate_limit.budget
        self._requests_used = 0

    def authorize(self, target: str, port: int | None = None) -> ScopeDecision:
        # 1. Budget 
        if self._requests_used >= self._budget:
            return ScopeDecision(False, f"request budget exhausted ({self._budget})")

        # 2. Excluded list always wins even over an otherwise-valid match ('_')
        if self._matches_any(target, self._excluded):
            return ScopeDecision(False, f"{target} is explicitly excluded")

        # 3. Must match something in the allowed target list
        if not self._matches_any(target, self._targets):
            return ScopeDecision(False, f"{target} is not in the allowed target list")

        # 4. Port check
        if port is not None and self._ports and port not in self._ports:
            return ScopeDecision(False, f"port {port} is not in the allowed port list")

        self._requests_used += 1
        return ScopeDecision(True, "authorized")

    def _matches_any(self, target: str, patterns: list[str]) -> bool:
        return any(self._matches_one(target, pattern) for pattern in patterns)

    def _matches_one(self, target: str, pattern: str) -> bool:
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            ip = ipaddress.ip_address(target)
            return ip in network
        except ValueError:
            pass  

        if target == pattern:
            return True
            
         # Subdomain inheritance

        if target.endswith("." + pattern):
            return True

        return False
