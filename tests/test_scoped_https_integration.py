import asyncio
import os
import ssl
import subprocess
import tempfile

from sh4q.config import Sh4qConfig
from sh4q.network import ScopedHTTPClient
from sh4q.scope import ScopeEngine


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="sh4q-tls-") as directory:
        key_path = os.path.join(directory, "key.pem")
        cert_path = os.path.join(directory, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-out", cert_path, "-days", "1",
                "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            ],
            check=True,
            capture_output=True,
        )

        server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ssl.load_cert_chain(cert_path, key_path)
        seen: list[bytes] = []

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            request = await reader.readuntil(b"\r\n\r\n")
            seen.append(request)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_ssl)
        port = server.sockets[0].getsockname()[1]
        scope = ScopeEngine(
            Sh4qConfig(
                **{
                    "scope": {
                        "targets": ["localhost"],
                        "ports": [port],
                        "allow_private_addresses": True,
                    }
                }
            )
        )

        async def resolve(host: str, requested_port: int) -> list[str]:
            assert host == "localhost"
            assert requested_port == port
            return ["127.0.0.1"]

        try:
            async with ScopedHTTPClient(
                scope,
                timeout=2,
                resolver=resolve,
                verify=cert_path,
            ) as client:
                response = await client.get(f"https://localhost:{port}/")
                assert response.status_code == 200
        finally:
            server.close()
            await server.wait_closed()

        assert len(seen) == 1
        assert b"Host: localhost:" in seen[0]
    print("scoped HTTPS integration test passed")


asyncio.run(main())
