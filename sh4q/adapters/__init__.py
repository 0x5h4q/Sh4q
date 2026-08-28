"""Contracts for future external reconnaissance-tool adapters."""

from .interface import AdapterContext, ExternalToolAdapter
from .plugin import ExternalAdapterPlugin
from .subfinder import SubfinderAdapter
from .httpx_fingerprint import HttpxFingerprintAdapter
from .runner import AdapterExecutionError, ControlledProcessRunner, ProcessResult

__all__ = [
    "AdapterContext",
    "AdapterExecutionError",
    "ControlledProcessRunner",
    "ExternalToolAdapter",
    "ExternalAdapterPlugin",
    "HttpxFingerprintAdapter",
    "SubfinderAdapter",
    "ProcessResult",
]
