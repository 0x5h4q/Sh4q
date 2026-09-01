"""Contracts for future external reconnaissance-tool adapters."""

from .interface import AdapterContext, ExternalToolAdapter
from .plugin import ExternalAdapterPlugin
from .subfinder import SubfinderAdapter
from .amass import AmassPassiveAdapter
from .httpx_fingerprint import HttpxFingerprintAdapter
from .httpx_plugin import HttpxFingerprintPlugin
from .httpx_identity import validate_projectdiscovery_httpx
from .runner import AdapterExecutionError, ControlledProcessRunner, ProcessResult

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
    "AmassPassiveAdapter",
    "ProcessResult",
]
