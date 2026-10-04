"""In-enclave network bootstrap: bring up loopback (down by default in a Nitro Enclave) and map api.github.com to it."""
from __future__ import annotations

import fcntl
import socket
import struct

from .forwarder import HOST_NAME

SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1


def loopback_up() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifr = struct.pack("16sH14s", b"lo", 0, b"")
        flags = struct.unpack("16sH14s", fcntl.ioctl(s, SIOCGIFFLAGS, ifr))[1]
        fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14s", b"lo", flags | IFF_UP, b""))
    finally:
        s.close()


def map_hosts(path: str = "/etc/hosts") -> None:
    line = f"127.0.0.1 {HOST_NAME}\n"
    try:
        current = open(path).read()
    except FileNotFoundError:
        current = ""
    if line not in current:
        with open(path, "a") as f:
            f.write(line)
