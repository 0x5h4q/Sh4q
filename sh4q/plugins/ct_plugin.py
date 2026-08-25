import asyncio

from .ct_connectors import (
    CertSpotterConnector,
    CrtShConnector,
    CTConnector,
    CTConnectorError,
)
from .discovery import Discovery
from .interface import Plugin, PluginMetadata


class CTPlugin(Plugin):
    metadata = PluginMetadata(
        name="ct",
        risk_level="passive",
        timeout=25.0,
    )

    def __init__(
        self,
        connectors: list[CTConnector] | None = None,
    ):
        self._connectors = connectors or [
            CertSpotterConnector(),
            CrtShConnector(),
        ]
        self._connector_timeout = 10.0

    async def _try_connector(
        self,
        connector: CTConnector,
        target: str,
    ):
        try:
            hostnames = await connector.fetch_hostnames(
                target,
                self._connector_timeout,
            )
            return connector.name, set(hostnames), None

        except CTConnectorError as e:
            return connector.name, e.partial_hostnames, e

    async def execute(
        self,
        target: str,
    ) -> list[Discovery]:
        results = await asyncio.gather(
            *(
                self._try_connector(
                    connector,
                    target,
                )
                for connector in self._connectors
            )
        )

        all_hostnames: set[str] = set()
        errors: list[tuple[str, CTConnectorError]] = []

        for source_name, hostnames, error in results:
            all_hostnames.update(hostnames)

            if error is not None:
                errors.append((source_name, error))

        print("CT providers:")
        for source_name, hostnames, error in results:
            if error is None:
                print(f"  {source_name:<14} success      {len(hostnames)} names")
            elif error.rate_limited:
                print(f"  {source_name:<14} rate-limited {str(error)}")
            elif hostnames:
                print(
                    f"  {source_name:<14} partial      "
                    f"{len(hostnames)} names; {str(error)}"
                )
            else:
                print(f"  {source_name:<14} degraded     {str(error)}")

        discoveries: list[Discovery] = []

        for source_name, hostnames, error in results:
            if error is None:
                status = "success"
            elif error.rate_limited:
                status = "rate_limited"
            elif hostnames:
                status = "partial"
            else:
                status = "degraded"

            discoveries.append(
                Discovery(
                    kind="ct_provider_status",
                    data={
                        "domain": target,
                        "source": source_name,
                        "status": status,
                        "names": len(hostnames),
                        "error": str(error) if error is not None else None,
                        "retryable": error.retryable if error is not None else False,
                        "rate_limited": error.rate_limited if error is not None else False,
                        "retry_after": error.retry_after if error is not None else None,
                    },
                )
            )

        for hostname in sorted(all_hostnames):
            sources = sorted(
                {
                    source_name
                    for source_name, hostnames, _ in results
                    if hostname in hostnames
                }
            )

            discoveries.append(
                Discovery(
                    kind="subdomain_found",
                    data={
                        "domain": target,
                        "hostname": hostname,
                        "source": ",".join(sources),
                    },
                )
            )

        if all_hostnames:
            return discoveries

        if errors:
            rate_limit_errors = [
                (source_name, error)
                for source_name, error in errors
                if error.rate_limited
            ]

            if rate_limit_errors:
                discoveries.append(
                    Discovery(
                        kind="ct_rate_limited",
                        data={
                            "domain": target,
                            "source": ",".join(
                                source_name
                                for source_name, _ in rate_limit_errors
                            ),
                            "error": "; ".join(
                                str(error)
                                for _, error in rate_limit_errors
                            ),
                            "retryable": False,
                            "retry_after": max(
                                (
                                    error.retry_after
                                    for _, error in rate_limit_errors
                                    if error.retry_after is not None
                                ),
                                default=None,
                            ),
                        },
                    )
                )
                return discoveries

            discoveries.append(
                Discovery(
                    kind="ct_error",
                    data={
                        "domain": target,
                        "source": ",".join(
                            source_name
                            for source_name, _ in errors
                        ),
                        "error": "; ".join(
                            str(error)
                            for _, error in errors
                        ),
                        "retryable": any(
                            error.retryable
                            for _, error in errors
                        ),
                    },
                )
            )
            return discoveries

        return []
