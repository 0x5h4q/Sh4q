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
            print(f"CT SOURCE: {connector.name} on {target}")

            hostnames = await connector.fetch_hostnames(
                target,
                self._connector_timeout,
            )

            print(
                f"CT SOURCE SUCCESS: {connector.name} "
                f"returned {len(hostnames)} hostname(s)"
            )

            return connector.name, set(hostnames), None

        except CTConnectorError as e:
            if e.partial_hostnames:
                print(
                    f"CT SOURCE PARTIAL: {connector.name} "
                    f"retained {len(e.partial_hostnames)} hostname(s)"
                )

            if e.rate_limited:
                print(
                    f"CT SOURCE RATE LIMITED: "
                    f"{connector.name}: {e}"
                )
            else:
                print(
                    f"CT SOURCE DEGRADED: "
                    f"{connector.name}: {e}"
                )

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

        discoveries: list[Discovery] = []

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

        if discoveries:
            if errors:
                for source_name, error in errors:
                    if error.rate_limited:
                        discoveries.append(
                            Discovery(
                                kind="ct_rate_limited",
                                data={
                                    "domain": target,
                                    "source": source_name,
                                    "error": str(error),
                                    "retryable": False,
                                    "retry_after": error.retry_after,
                                },
                            )
                        )

            return discoveries

        if errors:
            rate_limit_errors = [
                (source_name, error)
                for source_name, error in errors
                if error.rate_limited
            ]

            if rate_limit_errors:
                return [
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
                ]

            return [
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
            ]

        return []