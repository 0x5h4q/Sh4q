"""Contracts for future external reconnaissance-tool adapters."""

from .interface import AdapterContext, ExternalToolAdapter
from .plugin import ExternalAdapterPlugin
from .subfinder import SubfinderAdapter
from .url_history import URLHistoryAdapter
from .amass import AmassPassiveAdapter
from .httpx_fingerprint import HttpxFingerprintAdapter
from .httpx_plugin import HttpxFingerprintPlugin
from .httpx_identity import validate_projectdiscovery_httpx
from .amass_identity import parse_amass_version, validate_amass
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
    "parse_amass_version",
    "validate_amass",
    "SubfinderAdapter",
    "URLHistoryAdapter",
    "AmassPassiveAdapter",
    "ProcessResult",
    "KatanaAdapter",
]
