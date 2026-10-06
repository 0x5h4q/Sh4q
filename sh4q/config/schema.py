

from typing import Literal

from pydantic import BaseModel, Field, field_validator


CURRENT_CONFIG_SCHEMA_VERSION = 1


class ScopeConfig(BaseModel):
    targets: list[str] = Field(default_factory=list)          
    excluded: list[str] = Field(default_factory=list)         
    ports: list[int] = Field(default_factory=lambda: [80, 443])
    allow_private_addresses: bool = False


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


class HttpxAdapterConfig(BaseModel):
    max_endpoints: int = Field(default=200, ge=1, le=1000)
    timeout_seconds: float = Field(default=120.0, gt=0, le=600)


#: Certificate-transparency sources a config may name. The connectors
#: themselves live in `sh4q/plugins/ct_connectors.py`; importing that here
#: would close a cycle (config -> plugins -> network -> scope -> config), so
#: the two lists are kept in step by `tests/test_crt_name_connector.py`
#: rather than by an import.
CT_SOURCE_NAMES = ("certspotter", "crt.sh", "crt.name")

#: Contacted unless a config says otherwise. crt.name is excluded until an
#: operator asks for it.
DEFAULT_CT_SOURCES = ("certspotter", "crt.sh")


class CertificateTransparencyConfig(BaseModel):
    """Which certificate-transparency sources a scan may contact.

    Each source is a third party that learns which domain an operator is
    interested in. Naming them here makes that disclosure reviewable before a
    scan runs instead of being a property of the code. Narrowing the list is a
    disclosure control; widening it is an explicit choice.
    """

    sources: list[str] = Field(default_factory=lambda: list(DEFAULT_CT_SOURCES))

    @field_validator("sources")
    @classmethod
    def _known_sources(cls, value: list[str]) -> list[str]:
        unknown = [name for name in value if name not in CT_SOURCE_NAMES]
        if unknown:
            known = ", ".join(sorted(CT_SOURCE_NAMES))
            raise ValueError(
                f"unknown certificate transparency source(s): {', '.join(unknown)}; "
                f"known sources: {known}"
            )
        if not value:
            raise ValueError(
                "certificate_transparency.sources must name at least one source; "
                "disable the stage instead of emptying the list"
            )
        return list(dict.fromkeys(value))


class EnrichmentConfig(BaseModel):
    """How much of what a scan discovers it goes on to check.

    These are the bounds that decide coverage. The request budget usually is
    not: a real scan of a large estate used 316 of its 900 requests while
    leaving 711 discovered names unexamined, because the limit that bit was
    the number of names resolved, and that was not adjustable.
    """

    max_names_resolved: int = Field(default=500, ge=1, le=20000)
    max_hosts_probed: int = Field(default=200, ge=1, le=5000)
    #: Historical URLs retained per scan. waybackurls returned 14658 for one
    #: real target; the rest are selected across hosts rather than truncated.
    max_historical_urls: int = Field(default=5000, ge=1, le=200000)


class AdaptersConfig(BaseModel):
    httpx: HttpxAdapterConfig = Field(default_factory=HttpxAdapterConfig)


class Sh4qConfig(BaseModel):
    schema_version: Literal[CURRENT_CONFIG_SCHEMA_VERSION] = (
        CURRENT_CONFIG_SCHEMA_VERSION
    )
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    timeout: TimeoutConfig = Field(default_factory=TimeoutConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    adapters: AdaptersConfig = Field(default_factory=AdaptersConfig)
    enrichment: EnrichmentConfig = Field(default_factory=EnrichmentConfig)
    certificate_transparency: CertificateTransparencyConfig = Field(
        default_factory=CertificateTransparencyConfig
    )
