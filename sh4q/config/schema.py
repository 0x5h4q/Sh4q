

from pydantic import BaseModel, Field


class ScopeConfig(BaseModel):
    targets: list[str] = Field(default_factory=list)          
    excluded: list[str] = Field(default_factory=list)         
    ports: list[int] = Field(default_factory=lambda: [80, 443])


class RateLimitConfig(BaseModel):
    max_concurrent: int = Field(default=3, ge=1)   
    requests_per_second: float = Field(default=2.0, gt=0)
    budget: int = Field(default=1000, ge=1)


class TimeoutConfig(BaseModel):
    dns_seconds: float = Field(default=5.0, gt=0)
    http_seconds: float = Field(default=10.0, gt=0)


class OutputConfig(BaseModel):
    directory: str = "./sh4q-output"
    format: str = "json"   


class LoggingConfig(BaseModel):
    level: str = "INFO"
    structured: bool = True   


class Sh4qConfig(BaseModel):
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    timeout: TimeoutConfig = Field(default_factory=TimeoutConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)