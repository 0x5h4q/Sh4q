"""Contracts for future external reconnaissance-tool adapters."""

from .interface import AdapterContext, ExternalToolAdapter
from .plugin import ExternalAdapterPlugin
from .subfinder import SubfinderAdapter
from .httpx_fingerprint import HttpxFingerprintAdapter
from .httpx_plugin import HttpxFingerprintPlugin
from .runner import AdapterExecutionError, ControlledProcessRunner, ProcessResult

__all__ = [
    "AdapterContext",
    "AdapterExecutionError",
    "ControlledProcessRunner",
    "ExternalToolAdapter",
    "ExternalAdapterPlugin",
    "HttpxFingerprintAdapter",
    "HttpxFingerprintPlugin",
    "SubfinderAdapter",
    "ProcessResult",
]
