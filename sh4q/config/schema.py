
"""
sh4q/config/schema.py

Defines the SHAPE every config file must fit. This is what your original
project doc called the "Configuration Schema" — one of the six frozen
interfaces. Using pydantic here (not plain dicts) means a malformed config
gets rejected immediately with a clear error, instead of silently causing
weird behavior three layers deep in the engine later.
"""

from pydantic import BaseModel, Field


class ScopeConfig(BaseModel):
    """What's allowed to be scanned. This feeds directly into the Scope Engine."""
    targets: list[str] = Field(default_factory=list)          # hostnames/CIDRs allowed
    excluded: list[str] = Field(default_factory=list)         # explicit denylist, wins over targets
    ports: list[int] = Field(default_factory=lambda: [80, 443])


class RateLimitConfig(BaseModel):
    """How aggressively the engine is allowed to hit any single target."""
    max_concurrent: int = Field(default=3, ge=1)   # same concept as your toy project's semaphore
    requests_per_second: float = Field(default=2.0, gt=0)
    budget: int = Field(default=1000, ge=1)         # hard cap on total requests for a scan


class TimeoutConfig(BaseModel):
    dns_seconds: float = Field(default=5.0, gt=0)
    http_seconds: float = Field(default=10.0, gt=0)


class OutputConfig(BaseModel):
    directory: str = "./sh4q-output"
    format: str = "json"   # json | markdown | html — validated more strictly later


class LoggingConfig(BaseModel):
    level: str = "INFO"
    structured: bool = True   # JSON logging, per your original coding standards


class Sh4qConfig(BaseModel):
    """The single object the rest of the engine trusts. Everything else
    (Scope Engine, Scheduler, plugins) reads settings from THIS, never
    directly from a YAML file or environment variable."""
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    timeout: TimeoutConfig = Field(default_factory=TimeoutConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)