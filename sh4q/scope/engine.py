
import ipaddress
from dataclasses import dataclass
from enum import Enum

from sh4q.config import Sh4qConfig


class ScopeStatus(Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"   

@dataclass
class ScopeDecision:
    status: ScopeStatus
    reason: str

    @property
    def allowed(self) -> bool:
        return self.status is ScopeStatus.ALLOW

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
        # 1. Budget — a hard cap on total requests, regardless of target validity
        if self._requests_used >= self._budget:
            return ScopeDecision(ScopeStatus.DENY, f"request budget exhausted ({self._budget})")

        # 2. Excluded list always wins, even over an otherwise-valid match
        if self._matches_any(target, self._excluded):
            return ScopeDecision(ScopeStatus.DENY, f"{target} is explicitly excluded")

        # 3. Must match something in the allowed target list
        if not self._matches_any(target, self._targets):
            return ScopeDecision(ScopeStatus.DENY, f"{target} is not in the allowed target list")

        # 4. Port check, only if a port was actually specified
        if port is not None and self._ports and port not in self._ports:
            return ScopeDecision(ScopeStatus.DENY, f"port {port} is not in the allowed port list")

        self._requests_used += 1
        return ScopeDecision(ScopeStatus.ALLOW, "authorized")

    def _matches_any(self, target: str, patterns: list[str]) -> bool:
        return any(self._matches_one(target, pattern) for pattern in patterns)

    def _matches_one(self, target: str, pattern: str) -> bool:
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            ip = ipaddress.ip_address(target)
            return ip in network
        except ValueError:
            pass  

        # Exact hostname match
        if target == pattern:
            return True

        # Subdomain inheritance: "sub.example.com" is in scope if "example.com" is an allowed target
        if target.endswith("." + pattern):
            return True

        return False