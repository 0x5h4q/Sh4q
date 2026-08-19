
import asyncio
import socket

from .discovery import Discovery
from .interface import Plugin, PluginMetadata


class DNSPlugin(Plugin):
    metadata = PluginMetadata(
        name="dns",
        risk_level="passive",
        timeout=5.0,
    )

    async def execute(self, target: str) -> list[Discovery]:
        loop = asyncio.get_running_loop()

        try:
            results = await loop.getaddrinfo(target, None)

        except OSError as e:
            retryable = (
                isinstance(e, socket.gaierror)
                and e.errno == socket.EAI_AGAIN
            )

            return [
                Discovery(
                    kind="dns_error",
                    data={
                        "domain": target,
                        "error": str(e),
                        "retryable": retryable,
                    },
                )
            ]

        ips = sorted(
            {
                info[4][0]
                for info in results
            }
        )

        return [
            Discovery(
                kind="dns_resolution",
                data={
                    "domain": target,
                    "ip": ip,
                },
            )
            for ip in ips
        ]