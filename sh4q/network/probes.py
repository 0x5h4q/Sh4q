"""Turn an authorized port list into the endpoints a stage actually probes.

`scope.ports` is an authorization filter. These helpers are the other half:
they decide which origins a probing stage contacts, so that every authorized
port is reached rather than only the two well-known ones.
"""

from __future__ import annotations

import ipaddress


# Ports whose scheme is unambiguous in practice. Anything absent is probed
# over both schemes, because guessing wrong would silently skip a service.
PORT_SCHEMES: dict[int, tuple[str, ...]] = {
    80: ("http",),
    443: ("https",),
    591: ("http",),
    8000: ("http",),
    8008: ("http",),
    8080: ("http",),
    8081: ("http",),
    8088: ("http",),
    8888: ("http",),
    3000: ("http",),
    5000: ("http",),
    8443: ("https",),
    9443: ("https",),
    4443: ("https",),
}

# Used when the scope authorizes every port, so the probe set stays bounded
# instead of unbounded.
DEFAULT_PROBE_PORTS: tuple[int, ...] = (80, 443)


def schemes_for_port(port: int) -> tuple[str, ...]:
    return PORT_SCHEMES.get(port, ("https", "http"))


def probe_targets(ports) -> tuple[tuple[str, int], ...]:
    """Return the ordered (scheme, port) pairs to probe.

    An empty port list means the scope authorizes any port; probing every
    port is not an option, so the well-known pair is used instead.
    """
    effective = tuple(dict.fromkeys(ports)) or DEFAULT_PROBE_PORTS
    targets: list[tuple[str, int]] = []
    for port in sorted(set(effective)):
        for scheme in schemes_for_port(port):
            targets.append((scheme, port))
    return tuple(targets)


def primary_probe_target(ports) -> tuple[str, int]:
    """The single origin for stages that probe one endpoint per scan.

    Virtual-host and directory discovery sweep one origin rather than every
    authorized port, so that a candidate list is not multiplied by the port
    count. HTTPS is preferred when authorized, which keeps the long-standing
    behaviour for the default 80/443 scope.
    """
    targets = probe_targets(ports)
    for scheme, port in targets:
        if scheme == "https":
            return scheme, port
    return targets[0]


def probe_url(scheme: str, host: str, port: int, path: str = "") -> str:
    """Build a request URL, bracketing IPv6 literals and eliding default ports."""
    try:
        if ipaddress.ip_address(host).version == 6:
            host = f"[{host}]"
    except ValueError:
        pass
    default_port = 443 if scheme == "https" else 80
    authority = host if port == default_port else f"{host}:{port}"
    return f"{scheme}://{authority}{path}"
