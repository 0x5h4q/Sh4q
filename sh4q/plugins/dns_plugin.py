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
        try:
            results = await asyncio.to_thread(
                socket.getaddrinfo,
                target,
                None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            )
        except socket.gaierror as e:
            return [
                Discovery(
                    kind="dns_error",
                    data={
                        "domain": target,
                        "error": str(e),
                    },
                )
            ]
        except OSError as e:
            return [
                Discovery(
                    kind="dns_error",
                    data={
                        "domain": target,
                        "error": str(e),
                    },
                )
            ]

        ips = sorted(
            {
                info[4][0]
                for info in results
                if info[4]
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