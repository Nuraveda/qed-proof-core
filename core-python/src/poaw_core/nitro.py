"""AWS Nitro Enclaves attestation verification (SPEC.md §7.1, trust level 3).

`verify_nitro_attestation` checks the COSE_Sign1 document and its certificate chain to the pinned AWS Nitro root.
`verify_enclave_receipt` adds the receipt-level rules (PCR0 = code_hash, user_data = statement digest, published build).
Every failure raises `AttestationError` with one of the reason codes in `REASONS`.

CBOR: poaw_core stays at two dependencies, so instead of `cbor2` this module carries a small, strict decoder for exactly
the subset an attestation document uses (unsigned/negative ints, byte/text strings, arrays, maps, null/booleans, and tag
18 on the outer COSE_Sign1). It rejects indefinite lengths, floats, other tags, duplicate map keys, trailing bytes and
excessive nesting, which is stricter than a general library and easier to audit than one.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding

from . import b64u, b64u_decode, enclave_statement_digest

ATTESTATION_TYPE = "aws-nitro-enclave"
NITRO_ROOT_SHA256 = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
# AWS Nitro Enclaves root, G1 (https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip). Same bytes as
# spec/nitro-root.pem.
NITRO_ROOT_PEM = """-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
"""
NITRO_ROOT_DER = x509.load_pem_x509_certificate(NITRO_ROOT_PEM.encode()).public_bytes(Encoding.DER)
if hashlib.sha256(NITRO_ROOT_DER).hexdigest() != NITRO_ROOT_SHA256:  # fail loudly: never run with a wrong trust anchor
    raise RuntimeError("embedded AWS Nitro root does not match its pinned SHA-256 fingerprint")

REASONS = ("attestation_invalid", "attestation_chain", "pcr_mismatch", "statement_mismatch", "unknown_build")


class AttestationError(Exception):
    """An attestation that does not verify. `reason` is one of REASONS (SPEC §7.1)."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class NitroAttestation:
    module_id: str
    digest: str
    timestamp: int  # milliseconds since the Unix epoch, as the NSM reports it
    pcrs: dict[int, bytes]
    user_data: bytes | None
    nonce: bytes | None
    public_key: bytes | None


# --- strict CBOR subset decoder ------------------------------------------------------------------------------------
_MAX_DEPTH = 16


class _CborError(ValueError):
    pass


def _head(data: bytes, pos: int) -> tuple[int, int, int]:
    if pos >= len(data):
        raise _CborError("truncated")
    major, ai = data[pos] >> 5, data[pos] & 0x1F
    pos += 1
    if ai < 24:
        return major, ai, pos
    if ai == 31 and major in (2, 3, 4, 5):
        # Indefinite length (RFC 8949 §3.2): the real NSM encodes its attestation payload map this way. The COSE
        # signature still covers the exact bytes, so accepting it costs nothing; the caller reads until the break (0xff).
        return major, -1, pos
    if ai > 27:
        raise _CborError("reserved additional info")
    n = 1 << (ai - 24)
    if pos + n > len(data):
        raise _CborError("truncated")
    return major, int.from_bytes(data[pos:pos + n], "big"), pos + n


def _decode(data: bytes, pos: int, depth: int):
    if depth > _MAX_DEPTH:
        raise _CborError("nested too deeply")
    if pos < len(data) and data[pos] >> 5 == 7:  # simple values: only false/true/null
        simple = data[pos] & 0x1F
        if simple in (20, 21, 22):
            return (False, True, None)[simple - 20], pos + 1
        raise _CborError("unsupported simple value or float")
    major, arg, pos = _head(data, pos)
    if arg == -1:
        return _decode_indefinite(data, pos, major, depth)
    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major in (2, 3):
        if pos + arg > len(data):
            raise _CborError("truncated")
        raw = data[pos:pos + arg]
        if major == 2:
            return bytes(raw), pos + arg
        try:
            return raw.decode("utf-8"), pos + arg
        except UnicodeDecodeError as e:
            raise _CborError("invalid utf-8") from e
    if major == 4:
        if arg > len(data) - pos:  # every item takes at least one byte
            raise _CborError("truncated")
        out = []
        for _ in range(arg):
            item, pos = _decode(data, pos, depth + 1)
            out.append(item)
        return out, pos
    if major == 5:
        if arg > len(data) - pos:
            raise _CborError("truncated")
        m: dict = {}
        for _ in range(arg):
            k, pos = _decode(data, pos, depth + 1)
            if isinstance(k, bool) or not isinstance(k, (int, str, bytes)):
                raise _CborError("unsupported map key")
            if k in m:
                raise _CborError("duplicate map key")
            m[k], pos = _decode(data, pos, depth + 1)
        return m, pos
    raise _CborError("tags are only allowed on the outer COSE_Sign1")  # major 6


_BREAK = 0xFF


def _decode_indefinite(data: bytes, pos: int, major: int, depth: int):
    """Indefinite-length string, array or map, terminated by the break byte. Strings are definite-length chunks of the
    same major type (RFC 8949 §3.2.3)."""
    def at_break(p: int) -> bool:
        if p >= len(data):
            raise _CborError("truncated (no break)")
        return data[p] == _BREAK

    if major in (2, 3):
        parts = []
        while not at_break(pos):
            m, n, pos = _head(data, pos)
            if m != major or n < 0:
                raise _CborError("bad indefinite string chunk")
            if pos + n > len(data):
                raise _CborError("truncated")
            parts.append(bytes(data[pos:pos + n]))
            pos += n
        raw = b"".join(parts)
        if major == 2:
            return raw, pos + 1
        try:
            return raw.decode("utf-8"), pos + 1
        except UnicodeDecodeError as e:
            raise _CborError("invalid utf-8") from e
    if major == 4:
        out = []
        while not at_break(pos):
            item, pos = _decode(data, pos, depth + 1)
            out.append(item)
        return out, pos + 1
    m: dict = {}
    while not at_break(pos):
        k, pos = _decode(data, pos, depth + 1)
        if isinstance(k, bool) or not isinstance(k, (int, str, bytes)):
            raise _CborError("unsupported map key")
        if k in m:
            raise _CborError("duplicate map key")
        m[k], pos = _decode(data, pos, depth + 1)
    return m, pos + 1


def cbor_decode(data: bytes):
    """Decode exactly one CBOR item (the subset above). Raises ValueError otherwise."""
    value, pos = _decode(data, 0, 0)
    if pos != len(data):
        raise _CborError("trailing bytes")
    return value


# --- COSE_Sign1 + certificate chain --------------------------------------------------------------------------------
_COSE_ES384 = -35
_TAG_COSE_SIGN1 = 0xD2  # CBOR tag 18, one-byte head


def _is_bytes(v) -> bool:
    return isinstance(v, bytes)


def _bad(detail: str) -> AttestationError:
    return AttestationError("attestation_invalid", detail)


def _parse(document: bytes) -> tuple[bytes, dict, bytes, bytes]:
    """Return (protected bytes, payload map, payload bytes, signature) from a tagged or untagged COSE_Sign1."""
    try:
        if document[:1] == bytes([_TAG_COSE_SIGN1]):
            document = document[1:]
        cose = cbor_decode(document)
        if not (isinstance(cose, list) and len(cose) == 4 and _is_bytes(cose[0]) and isinstance(cose[1], dict)
                and _is_bytes(cose[2]) and _is_bytes(cose[3])):
            raise _bad("not a COSE_Sign1 array of four")
        protected, _, payload_bytes, signature = cose
        if cbor_decode(protected) != {1: _COSE_ES384}:
            raise _bad("protected header is not {alg: ES384}")
        payload = cbor_decode(payload_bytes)
    except _CborError as e:
        raise _bad(f"cbor: {e}") from e
    if not isinstance(payload, dict):
        raise _bad("payload is not a map")
    return protected, payload, payload_bytes, signature


def _fields(p: dict) -> NitroAttestation:
    def need(key: str, typ, *, optional: bool = False):
        v = p.get(key)
        if v is None and optional:
            return None
        if isinstance(v, bool) or not isinstance(v, typ):
            raise _bad(f"payload field {key!r} missing or of the wrong type")
        return v

    pcrs = need("pcrs", dict)
    if not pcrs or any(isinstance(k, bool) or not isinstance(k, int) or not _is_bytes(v) for k, v in pcrs.items()):
        raise _bad("pcrs must be a non-empty map of int to bytes")
    digest = need("digest", str)
    if digest != "SHA384":
        raise _bad("digest is not SHA384")
    return NitroAttestation(
        module_id=need("module_id", str), digest=digest, timestamp=need("timestamp", int), pcrs=dict(pcrs),
        user_data=need("user_data", bytes, optional=True), nonce=need("nonce", bytes, optional=True),
        public_key=need("public_key", bytes, optional=True))


def _verify_chain(root_der: bytes, bundle: list, leaf_der: bytes, when: datetime) -> x509.Certificate:
    """§7.1 step 2: cabundle[0] is the pinned root; root → … → leaf verify, intermediates are CAs, all valid at `when`."""
    if not bundle or not all(_is_bytes(c) for c in bundle) or not _is_bytes(leaf_der):
        raise _bad("cabundle/certificate missing or malformed")
    if bundle[0] != root_der:
        raise AttestationError("attestation_chain", "cabundle[0] is not the trusted root")
    try:
        chain = [x509.load_der_x509_certificate(d) for d in [*bundle, leaf_der]]
        for i, cert in enumerate(chain):
            if not cert.not_valid_before_utc <= when <= cert.not_valid_after_utc:
                raise AttestationError("attestation_chain", f"certificate {i} is not valid at the attestation time")
        for i in range(len(chain) - 1):
            issuer = chain[i]
            bc = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not bc.ca:
                raise AttestationError("attestation_chain", f"certificate {i} is not a CA")
            if bc.path_length is not None and len(chain) - 2 - i > bc.path_length:
                raise AttestationError("attestation_chain", f"certificate {i} path length exceeded")
            chain[i + 1].verify_directly_issued_by(issuer)
    except AttestationError:
        raise
    except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound) as e:
        raise AttestationError("attestation_chain", f"chain does not verify ({type(e).__name__})") from e
    return chain[-1]


def verify_nitro_attestation(document_b64u: str, *, root_der: bytes | None = None,
                             at: datetime | None = None) -> NitroAttestation:
    """SPEC §7.1 steps 1–3. `root_der` replaces the pinned AWS root (tests only). `at` replaces the document's own timestamp
    as the time certificates must be valid at. Raises AttestationError(attestation_invalid | attestation_chain)."""
    try:
        document = b64u_decode(document_b64u)
    except Exception as e:
        raise _bad("document is not base64url") from e
    protected, payload, payload_bytes, signature = _parse(document)
    att = _fields(payload)
    when = at if at is not None else datetime.fromtimestamp(att.timestamp / 1000, tz=timezone.utc)
    leaf = _verify_chain(root_der if root_der is not None else NITRO_ROOT_DER, payload.get("cabundle"),
                         payload.get("certificate"), when)
    pub = leaf.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp384r1" or len(signature) != 96:
        raise _bad("leaf key is not P-384 or signature is not 96 bytes")
    sig_structure = b"\x84" + b"\x6aSignature1" + _bstr(protected) + b"\x40" + _bstr(payload_bytes)  # ["Signature1", protected, h'', payload]
    try:
        pub.verify(encode_dss_signature(int.from_bytes(signature[:48], "big"), int.from_bytes(signature[48:], "big")),
                   sig_structure, ec.ECDSA(hashes.SHA384()))
    except InvalidSignature as e:
        raise _bad("COSE signature does not verify") from e
    return att


def _bstr(b: bytes) -> bytes:
    n = len(b)
    head = bytes([0x40 | n]) if n < 24 else b"\x58" + bytes([n]) if n < 256 else b"\x59" + n.to_bytes(2, "big") \
        if n < 65536 else b"\x5a" + n.to_bytes(4, "big")
    return head + b


_CODE_HASH = re.compile(r"sha384:[0-9a-f]{96}")


def attestation_document_sha256(document_b64u: str) -> str:
    """SPEC §4: base64url(SHA-256(raw COSE_Sign1 bytes)), the value a level-3 body carries as `attestation.document_sha256`."""
    return b64u(hashlib.sha256(b64u_decode(document_b64u)).digest())


def verify_enclave_receipt(receipt: dict, verifier_builds: list[dict] | None, *,
                           root_der: bytes | None = None, at: datetime | None = None) -> NitroAttestation:
    """SPEC §7.1 steps 1–5 for a whole receipt object at trust level >= 3. The body commits to the document by hash
    (`attestation.document_sha256`); the document itself is the receipt's top-level `attestation_document`.
    `verifier_builds` is the issuer's poaw-keys.json list. Raises AttestationError with one of REASONS; returns the
    parsed attestation when everything holds."""
    body = receipt.get("body") if isinstance(receipt, dict) else None
    attestation = body.get("attestation") if isinstance(body, dict) else None
    if not isinstance(attestation, dict) or attestation.get("type") != ATTESTATION_TYPE or not isinstance(
            attestation.get("document_sha256"), str):
        raise _bad("attestation is not an aws-nitro-enclave document hash")
    document = receipt.get("attestation_document")
    if not isinstance(document, str) or not document:
        raise _bad("the receipt carries no attestation_document")
    try:
        digest_ok = attestation_document_sha256(document) == attestation["document_sha256"]
    except Exception as e:
        raise _bad("attestation_document is not base64url") from e
    if not digest_ok:
        raise _bad("attestation_document does not match attestation.document_sha256")
    att = verify_nitro_attestation(document, root_der=root_der, at=at)
    try:
        code_hash = body["observation"]["verifier"]["code_hash"]
        digest = enclave_statement_digest(body)
    except (KeyError, TypeError) as e:
        raise _bad("receipt body lacks the fields the statement covers") from e
    pcr0 = att.pcrs.get(0)
    if not isinstance(code_hash, str) or not _CODE_HASH.fullmatch(code_hash) or pcr0 is None \
            or code_hash != "sha384:" + pcr0.hex():
        raise AttestationError("pcr_mismatch", "PCR0 is not the receipt's code_hash")
    if att.user_data != digest:
        raise AttestationError("statement_mismatch", "user_data is not the statement digest")
    if not any(isinstance(b, dict) and b.get("code_hash") == code_hash for b in verifier_builds or []):
        raise AttestationError("unknown_build", "code_hash is not a published verifier build")
    return att
