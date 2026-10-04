"""Nitro Security Module client: obtain an attestation document from /dev/nsm.

Approach: a ~40 line ctypes ioctl against the NSM driver plus `cbor2` (pinned, pure-Python fallback, no native build)
for the request/response encoding. We did not use a third-party NSM package: the known ones are thin, unpinned or
Rust-built wheels, and the kernel interface is tiny and public (aws-nitro-enclaves-nsm-api, `nsm-io`/`nsm-driver`).

Wire shape (aws-nitro-enclaves-nsm-api):
  ioctl(fd, NSM_IOCTL = _IOWR(0x0A, 0, struct nsm_message), &msg)
  struct nsm_message { struct iovec request; struct iovec response; }   // iovec = {void *base; size_t len}
  request  (CBOR): {"Attestation": {"user_data": bstr|null, "nonce": bstr|null, "public_key": bstr|null}}
  response (CBOR): {"Attestation": {"document": bstr}}  or  {"Error": "<ErrorCode>"}
`document` is the COSE_Sign1 (CBOR tag 18) attestation document, returned to callers unchanged.
"""
from __future__ import annotations

import ctypes
import fcntl
import os
from typing import Protocol

import cbor2

NSM_DEVICE = "/dev/nsm"
NSM_RESPONSE_MAX = 0x3000  # NSM_RESPONSE_MAX_SIZE in the driver
_IOC_READ_WRITE = 3
NSM_IOCTL = (_IOC_READ_WRITE << 30) | (2 * 2 * 8 << 16) | (0x0A << 8) | 0  # 0xC0200A00 on 64-bit


class Nsm(Protocol):
    def attest(self, user_data: bytes) -> bytes:
        """Return the COSE_Sign1 attestation document whose user_data is exactly `user_data`."""


class NsmError(RuntimeError):
    pass


class _Iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]


class _Message(ctypes.Structure):
    _fields_ = [("request", _Iovec), ("response", _Iovec)]


def encode_attestation_request(user_data: bytes) -> bytes:
    return cbor2.dumps({"Attestation": {"user_data": user_data, "nonce": None, "public_key": None}})


def decode_attestation_response(raw: bytes) -> bytes:
    resp = cbor2.loads(raw)
    if isinstance(resp, dict) and "Attestation" in resp and isinstance(resp["Attestation"], dict):
        doc = resp["Attestation"].get("document")
        if isinstance(doc, bytes) and doc:
            return doc
    raise NsmError(f"NSM attestation failed: {resp.get('Error') if isinstance(resp, dict) else 'bad response'}")


class DeviceNsm:
    def __init__(self, device: str = NSM_DEVICE):
        self.device = device

    def attest(self, user_data: bytes) -> bytes:
        if len(user_data) != 32:
            raise ValueError("user_data must be the 32-byte statement digest")
        req = encode_attestation_request(user_data)
        req_buf = ctypes.create_string_buffer(req, len(req))
        resp_buf = ctypes.create_string_buffer(NSM_RESPONSE_MAX)
        msg = _Message(_Iovec(ctypes.addressof(req_buf), len(req)), _Iovec(ctypes.addressof(resp_buf), NSM_RESPONSE_MAX))
        fd = os.open(self.device, os.O_RDWR)
        try:
            fcntl.ioctl(fd, NSM_IOCTL, msg)
        finally:
            os.close(fd)
        return decode_attestation_response(resp_buf.raw[: msg.response.len])


class FakeNsm:
    """Test double: returns a recognisable fake document embedding user_data. NOT a real attestation."""

    def __init__(self, fail: bool = False):
        self.fail = fail
        self.calls: list[bytes] = []

    def attest(self, user_data: bytes) -> bytes:
        self.calls.append(user_data)
        if self.fail:
            raise NsmError("fake NSM failure")
        return cbor2.dumps({"fake": True, "user_data": user_data})
