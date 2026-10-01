
import ipaddress
import unicodedata
from dataclasses import dataclass
from enum import Enum

from sh4q.config import Sh4qConfig


def _is_addressable(value: str, *, allow_network: bool = False) -> bool:
    """Whether a normalized value can name something on a network.

    An IP address, or a hostname whose labels are all non-empty and free of
    characters a hostname cannot carry. `allow_network` additionally accepts a
    CIDR block, which is valid in a scope pattern but never as a destination.
    """
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    if allow_network:
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            pass
    labels = value.split(".")
    if not all(labels):
        return False
    # A hostname label cannot be empty, cannot exceed 63 octets, and cannot
    # contain a wildcard, whitespace, or an authority delimiter. Certificate
    # transparency emits "*.example.com" for a wildcard certificate; the
    # connectors strip that prefix, and anything that still carries one is not
    # a name that could be contacted.
    forbidden = set("*?!/\\@:#[]%,'\" \t")
    return all(len(label) <= 63 and not (forbidden & set(label)) for label in labels)


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
        self._allow_private_addresses = config.scope.allow_private_addresses

    @property
    def authorized_ports(self) -> tuple[int, ...]:
        """Ports this scope permits. Empty means every port is authorized."""
        return tuple(sorted(self._ports))

    def authorize(self, target: str, port: int | None = None) -> ScopeDecision:
        target = self.normalize_target(target)
        # Subdomain inheritance is granted by `endswith("." + pattern)`, which
        # strings that are not hostnames also satisfy: ".example.com",
        # "..example.com" and "*.example.com" all matched "example.com" and
        # were authorized, became domain nodes, and were handed on to be
        # resolved. Refuse them here rather than relying on each emitter to
        # filter first.
        if not _is_addressable(target):
            return ScopeDecision(
                ScopeStatus.DENY, f"{target} is not a usable hostname or address"
            )
        # Excluded list always wins, even over an otherwise-valid match.
        if self._matches_any(target, self._excluded):
            return ScopeDecision(ScopeStatus.DENY, f"{target} is explicitly excluded")

        # The target must match something in the allowed target list.
        if not self._matches_any(target, self._targets):
            return ScopeDecision(ScopeStatus.DENY, f"{target} is not in the allowed target list")

        # Check the port only when one was specified.
        if port is not None and self._ports and port not in self._ports:
            return ScopeDecision(ScopeStatus.DENY, f"port {port} is not in the allowed port list")

        return ScopeDecision(ScopeStatus.ALLOW, "authorized")

    def authorize_resolved_address(self, address: str) -> ScopeDecision:
        """Apply network-address safety policy after hostname authorization."""
        try:
            ip = ipaddress.ip_address(self.normalize_target(address))
        except ValueError:
            return ScopeDecision(ScopeStatus.DENY, f"{address} is not a valid IP address")
        unsafe = any(
            (
                ip.is_private,
                ip.is_loopback,
                ip.is_link_local,
                ip.is_multicast,
                ip.is_reserved,
                ip.is_unspecified,
            )
        )
        if unsafe and not self._allow_private_addresses:
            return ScopeDecision(ScopeStatus.DENY, f"{ip} is a reserved or non-public address")
        return ScopeDecision(ScopeStatus.ALLOW, "resolved address authorized")

    def _matches_any(self, target: str, patterns: list[str]) -> bool:
        return any(self._matches_one(target, pattern) for pattern in patterns)

    def _matches_one(self, target: str, pattern: str) -> bool:
        target = self.normalize_target(target)
        pattern = self.normalize_target(pattern)
        # A malformed pattern matches nothing. Otherwise an operator typo such
        # as ".example.com" in the target list would act as a looser rule than
        # the hostname it was meant to be.
        if not _is_addressable(pattern, allow_network=True):
            return False
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

    @staticmethod
    def normalize_target(target: str) -> str:
        """Normalize hostnames and IP text before policy comparisons."""
        value = unicodedata.normalize("NFKC", str(target)).strip()
        if value.endswith("."):
            value = value[:-1]
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            try:
                return value.encode("idna").decode("ascii").casefold()
            except UnicodeError:
                return value.casefold()
