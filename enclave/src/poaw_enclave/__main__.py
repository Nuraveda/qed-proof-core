"""Enclave entrypoint: start the vsock->TCP forwarder (127.0.0.1:443) and the request server (vsock 5005)."""
import asyncio

from .bootstrap import loopback_up, map_hosts
from .forwarder import start_forwarder
from .nsm import DeviceNsm
from .server import make_http_client, serve


async def main() -> None:
    loopback_up()
    map_hosts()
    fwd = await start_forwarder()
    srv = await serve(nsm=DeviceNsm(), http=make_http_client())
    await asyncio.gather(fwd.serve_forever(), srv.serve_forever())


if __name__ == "__main__":
    asyncio.run(main())
