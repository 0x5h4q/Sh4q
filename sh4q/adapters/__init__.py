"""Contracts for future external reconnaissance-tool adapters."""

from .interface import AdapterContext, ExternalToolAdapter
from .plugin import ExternalAdapterPlugin
from .runner import AdapterExecutionError, ControlledProcessRunner, ProcessResult

__all__ = [
    "AdapterContext",
    "AdapterExecutionError",
    "ControlledProcessRunner",
    "ExternalToolAdapter",
    "ExternalAdapterPlugin",
    "ProcessResult",
]
