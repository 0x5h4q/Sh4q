"""Contracts for future external reconnaissance-tool adapters."""

from .interface import AdapterContext, ExternalToolAdapter
from .plugin import ExternalAdapterPlugin
from .subfinder import SubfinderAdapter
from .url_history import URLHistoryAdapter
from .httpx_fingerprint import HttpxFingerprintAdapter
from .httpx_plugin import HttpxFingerprintPlugin
from .httpx_identity import validate_projectdiscovery_httpx
from .runner import AdapterExecutionError, ControlledProcessRunner, ProcessResult
from .katana import KatanaAdapter

__all__ = [
    "AdapterContext",
    "AdapterExecutionError",
    "ControlledProcessRunner",
    "ExternalToolAdapter",
    "ExternalAdapterPlugin",
    "HttpxFingerprintAdapter",
    "HttpxFingerprintPlugin",
    "validate_projectdiscovery_httpx",
    "SubfinderAdapter",
    "URLHistoryAdapter",
    "ProcessResult",
    "KatanaAdapter",
]


#: Which third parties each external tool is documented to contact, and how
#: certain that is. Declared from documentation rather than observed: the
#: subprocess makes calls sh4q never sees, and a tool's real source list
#: changes with its version. Tools that contact only the scan's own target --
#: katana crawls it, httpx fingerprints it -- disclose to no third party and
#: are deliberately absent.
ADAPTER_DISCLOSURES: dict[str, tuple[tuple[str, ...], str]] = {
    "subfinder": (
        ("subfinder passive sources",),
        "many sources, version-dependent and set by the tool's own config; "
        "sh4q cannot observe which were queried",
    ),
    "url-history": (
        ("web.archive.org",),
        "documented source for waybackurls",
    ),
}
