"""In-enclave TCP -> vsock forwarder. /etc/hosts maps api.github.com to 127.0.0.1, so the verifier's HTTP client
connects here; bytes are relayed over vsock (parent CID 3, port 8443) to the host's `vsock-proxy`, which allow-lists
api.github.com:443. TLS is end to end: the enclave verifies the certificate against the image's CA bundle, so the
host sees only ciphertext and cannot alter responses."""
from __future__ import annotations

import asyncio
import socket
from typing import Callable

from . import FORWARD_VSOCK_PORT, PARENT_CID

HOST_NAME = "api.github.com"


def vsock_connect() -> socket.socket:
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.setblocking(False)
    return s


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def forward(upstream_connect: Callable[[], socket.socket], reader, writer, *, address=(PARENT_CID, FORWARD_VSOCK_PORT)):
    loop = asyncio.get_running_loop()
    sock = upstream_connect()
    try:
        await loop.sock_connect(sock, address)
        up_r, up_w = await asyncio.open_connection(sock=sock)
    except OSError:
        sock.close()
        writer.close()
        return
    await asyncio.gather(_pipe(reader, up_w), _pipe(up_r, writer))


async def start_forwarder(host: str = "127.0.0.1", port: int = 443, *, upstream_connect=vsock_connect,
                          address=(PARENT_CID, FORWARD_VSOCK_PORT)) -> asyncio.AbstractServer:
    return await asyncio.start_server(lambda r, w: forward(upstream_connect, r, w, address=address), host, port)
