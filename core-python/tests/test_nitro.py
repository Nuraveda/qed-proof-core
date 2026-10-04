"""SPEC §7.1: the attested statement and the Nitro attestation verifier, against a locally built test chain."""
import copy
import datetime as dt
import hashlib
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

import poaw_core as p
from poaw_core import nitro as n

UTC = dt.timezone.utc
T0 = dt.datetime(2026, 9, 25, 14, 2, 11, tzinfo=UTC)
TS_MS = int(T0.timestamp() * 1000)


def cbor(v) -> bytes:
    def head(major, k):
        if k < 24:
            return bytes([major << 5 | k])
        size = 1 if k < 256 else 2 if k < 65536 else 4 if k < 2**32 else 8
        return bytes([major << 5 | 24 + {1: 0, 2: 1, 4: 2, 8: 3}[size]]) + k.to_bytes(size, "big")
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(map(cbor, v))
    return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())


def cert(cn, key, issuer_cn, issuer_key, *, ca, path_length=None, nb=dt.datetime(2026, 1, 1, tzinfo=UTC),
         na=dt.datetime(2036, 1, 1, tzinfo=UTC)):
    name = lambda c: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, c)])
    return (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(issuer_cn)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(na)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
            .sign(issuer_key, hashes.SHA384()).public_bytes(Encoding.DER))


def make_chain(*, inter_ca=True, leaf_na=dt.datetime(2036, 1, 1, tzinfo=UTC)):
    rk, ik, lk = (ec.generate_private_key(ec.SECP384R1()) for _ in range(3))
    root = cert("root", rk, "root", rk, ca=True)
    inter = cert("inter", ik, "root", rk, ca=inter_ca, path_length=0 if inter_ca else None)
    leaf = cert("leaf", lk, "inter", ik, ca=False, na=leaf_na)
    return root, inter, leaf, lk


PCR0 = hashlib.sha384(b"build").digest()


def doc(chain, *, user_data=b"\x00" * 32, pcr0=PCR0, tagged=True, protected=None, extra=None, timestamp=TS_MS):
    root, inter, leaf, lk = chain
    payload_map = {"module_id": "i-1-enc1", "digest": "SHA384", "timestamp": timestamp, "pcrs": {0: pcr0, 1: b"\x01" * 48},
                   "certificate": leaf, "cabundle": [root, inter], "public_key": None, "user_data": user_data, "nonce": None}
    payload_map.update(extra or {})
    payload = cbor(payload_map)
    prot = protected if protected is not None else cbor({1: -35})
    r, s = decode_dss_signature(lk.sign(cbor(["Signature1", prot, b"", payload]), ec.ECDSA(hashes.SHA384())))
    raw = cbor([prot, {}, payload, r.to_bytes(48, "big") + s.to_bytes(48, "big")])
    return p.b64u((b"\xd2" if tagged else b"") + raw), payload, prot, r.to_bytes(48, "big") + s.to_bytes(48, "big")


@pytest.fixture(scope="module")
def chain():
    return make_chain()


def body(verdict=None):
    return {"claim": {"claim_digest": "abc", "action": "github.commit.push"},
            "observation": {"verifier": {"id": "github.commit.push", "version": "1", "code_hash": "sha384:" + PCR0.hex()},
                            "observed_at": "2026-09-25T14:02:11.000Z", "facts": {"found": True, "sha": "ab"}},
            "verdict": verdict or {"value": "verified"}}


def reason(fn, *a, **k):
    with pytest.raises(n.AttestationError) as e:
        fn(*a, **k)
    return e.value.reason


# --- C1 -------------------------------------------------------------------------------------------------------------
def test_statement_is_exactly_the_five_fields():
    b = body()
    b["observation"]["deadline_at"] = "x"; b["issuer"] = {"key_id": "k"}; b["trust_level"] = 3
    assert p.enclave_statement(b) == {
        "claim_digest": "abc", "verifier": {"id": "github.commit.push", "version": "1"},
        "observed_at": "2026-09-25T14:02:11.000Z", "facts": {"found": True, "sha": "ab"}, "verdict": {"value": "verified"}}


def test_statement_digest_is_sha256_of_jcs_and_binds_every_field():
    b = body()
    assert p.enclave_statement_digest(b) == hashlib.sha256(p.jcs(p.enclave_statement(b))).digest()
    assert p.enclave_statement_digest(b) == p.enclave_statement_digest(copy.deepcopy(b))
    for mutate in (lambda x: x["claim"].update(claim_digest="abd"), lambda x: x["observation"]["verifier"].update(version="2"),
                   lambda x: x["observation"].update(observed_at="2026-09-25T14:02:12.000Z"),
                   lambda x: x["observation"]["facts"].update(sha="ac"), lambda x: x.update(verdict={"value": "failed", "reason_code": "not_found"})):
        c = copy.deepcopy(b); mutate(c)
        assert p.enclave_statement_digest(c) != p.enclave_statement_digest(b)


def test_statement_does_not_alias_the_body():
    b = body(); s = p.enclave_statement(b); s["facts"]["found"] = False
    assert b["observation"]["facts"]["found"] is True


# --- pinned root ----------------------------------------------------------------------------------------------------
def test_pinned_root_matches_fingerprint_and_spec_file():
    assert hashlib.sha256(n.NITRO_ROOT_DER).hexdigest() == "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
    spec = Path(__file__).parents[2] / "spec" / "nitro-root.pem"
    if spec.exists():
        assert spec.read_text() == n.NITRO_ROOT_PEM


# --- C3 steps 1-3 ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("tagged", [True, False])
def test_valid_document(chain, tagged):
    d = doc(chain, user_data=b"\x07" * 32, tagged=tagged)[0]
    a = n.verify_nitro_attestation(d, root_der=chain[0])
    assert (a.module_id, a.digest, a.timestamp, a.pcrs[0], a.user_data, a.nonce, a.public_key) == (
        "i-1-enc1", "SHA384", TS_MS, PCR0, b"\x07" * 32, None, None)


def test_real_root_is_the_default_so_a_test_chain_fails(chain):
    assert reason(n.verify_nitro_attestation, doc(chain)[0]) == "attestation_chain"


def test_other_root_is_a_chain_failure(chain):
    assert reason(n.verify_nitro_attestation, doc(chain)[0], root_der=make_chain()[0]) == "attestation_chain"


def test_tampered_payload_is_invalid(chain):
    _, payload, prot, sig = doc(chain)
    bad = payload.replace(b"enc1", b"enc2", 1)
    raw = p.b64u(cbor([prot, {}, bad, sig]))
    assert reason(n.verify_nitro_attestation, raw, root_der=chain[0]) == "attestation_invalid"


def test_signature_by_wrong_key_is_invalid(chain):
    other = make_chain()
    root, inter, leaf, _ = chain
    d = doc((root, inter, leaf, other[3]))[0]  # signed with a key that is not the leaf's
    assert reason(n.verify_nitro_attestation, d, root_der=root) == "attestation_invalid"


def test_wrong_alg_header_is_invalid(chain):
    assert reason(n.verify_nitro_attestation, doc(chain, protected=cbor({1: -7}))[0], root_der=chain[0]) == "attestation_invalid"


def test_expired_leaf_and_time_override(chain):
    short = make_chain(leaf_na=dt.datetime(2026, 9, 25, tzinfo=UTC))
    assert reason(n.verify_nitro_attestation, doc(short)[0], root_der=short[0]) == "attestation_chain"  # doc time is after expiry
    assert n.verify_nitro_attestation(doc(short)[0], root_der=short[0], at=dt.datetime(2026, 9, 24, tzinfo=UTC))


def test_non_ca_intermediate_is_a_chain_failure():
    c = make_chain(inter_ca=False)
    assert reason(n.verify_nitro_attestation, doc(c)[0], root_der=c[0]) == "attestation_chain"


def test_missing_or_bad_fields(chain):
    assert reason(n.verify_nitro_attestation, doc(chain, extra={"digest": "SHA256"})[0], root_der=chain[0]) == "attestation_invalid"
    assert reason(n.verify_nitro_attestation, doc(chain, extra={"pcrs": {}})[0], root_der=chain[0]) == "attestation_invalid"
    assert reason(n.verify_nitro_attestation, doc(chain, extra={"timestamp": "now"})[0], root_der=chain[0]) == "attestation_invalid"
    assert reason(n.verify_nitro_attestation, doc(chain, extra={"cabundle": []})[0], root_der=chain[0]) == "attestation_invalid"
    assert reason(n.verify_nitro_attestation, "!!!", root_der=chain[0]) == "attestation_invalid"


@pytest.mark.parametrize("raw", [
    # Indefinite-length items are ACCEPTED since 2026-10-04: real NSM documents encode their payload map that way (see
    # test_a_real_aws_document_verifies_against_the_pinned_root). Their malformed forms stay rejected below.
    b"", b"\x84", b"\x9f\x01",                  # empty, truncated, indefinite array with no break
    b"\x01\x02",                                 # trailing bytes
    b"\xa2\x01\x01\x01\x02",                     # duplicate map key
    b"\xc1\x01",                                 # tag other than 18
    b"\xfb\x3f\xf0\x00\x00\x00\x00\x00\x00",     # float
    b"\x5f\x61\x01\xff",                         # indefinite byte string with a text-string chunk
    b"\x61\xff",                                 # invalid utf-8
    b"\x81" * 40 + b"\x00",                      # nesting too deep
])
def test_cbor_decoder_is_strict(raw):
    with pytest.raises(ValueError):
        n.cbor_decode(raw)


def test_cbor_decoder_roundtrips_the_subset():
    v = {"a": [1, -1, 24, 70000, b"x", None, True], 3: {0: b"\x00"}}
    assert n.cbor_decode(cbor({k: x for k, x in v.items() if k != "a"})) == {3: {0: b"\x00"}}
    assert n.cbor_decode(cbor([1, -1, 24, 70000, b"x", None])) == [1, -1, 24, 70000, b"x", None]


# --- C3 steps 4-5 ---------------------------------------------------------------------------------------------------
def receipt_and_builds(chain, **kw):
    b = body()
    document = doc(chain, user_data=p.enclave_statement_digest(b), **kw)[0]
    b["attestation"] = {"type": "aws-nitro-enclave", "document_sha256": n.attestation_document_sha256(document)}
    return {"body": b, "signature": {}, "attestation_document": document}, [{"code_hash": "sha384:" + PCR0.hex()}]


def test_receipt_verifies(chain):
    rc, builds = receipt_and_builds(chain)
    assert n.verify_enclave_receipt(rc, builds, root_der=chain[0]).pcrs[0] == PCR0


def test_receipt_reasons(chain):
    rc, builds = receipt_and_builds(chain)
    r = lambda rc=rc, builds=builds: reason(n.verify_enclave_receipt, rc, builds, root_der=chain[0])
    with_body = lambda mut: {**rc, "body": mut(copy.deepcopy(rc["body"]))}
    assert r(builds=[]) == "unknown_build"
    assert r(builds=None) == "unknown_build"
    other = copy.deepcopy(rc["body"]); other["observation"]["verifier"]["code_hash"] = "sha384:" + hashlib.sha384(b"x").hexdigest()
    assert r(rc={**rc, "body": other}, builds=[{"code_hash": other["observation"]["verifier"]["code_hash"]}]) == "pcr_mismatch"
    def alter(b):
        b["verdict"] = {"value": "failed", "reason_code": "not_found"}
        return b
    assert r(rc=with_body(alter)) == "statement_mismatch"
    def other_type(b):
        b["attestation"]["type"] = "other"
        return b
    assert r(rc=with_body(other_type)) == "attestation_invalid"
    assert r(rc=with_body(lambda b: {k: v for k, v in b.items() if k != "attestation"})) == "attestation_invalid"
    assert r(rc={k: v for k, v in rc.items() if k != "attestation_document"}) == "attestation_invalid"  # document absent
    assert r(rc={**rc, "attestation_document": rc["attestation_document"][:-4] + "AAAA"}) == "attestation_invalid"  # hash mismatch
    assert r(rc={**rc, "attestation_document": "!!!"}) == "attestation_invalid"
    assert reason(n.verify_enclave_receipt, rc, builds) == "attestation_chain"  # no override => real AWS root


def test_a_real_aws_document_verifies_against_the_pinned_root():
    """Real NSM output (enclave build 2, 2026-10-04). It encodes its payload as an indefinite-length CBOR map, which the
    hand-made test vectors never did; this is the regression test for that."""
    import json
    from pathlib import Path

    from poaw_core import nitro as N

    fx = json.loads((Path(__file__).parent / "fixtures" / "nitro-live-build2.json").read_text())
    att = N.verify_nitro_attestation(fx["attestation"])  # pinned AWS root, certificates checked at the document's time
    assert att.pcrs[0].hex() == fx["expected_pcr0"]
    assert att.digest == "SHA384" and len(att.user_data) == 32


def test_indefinite_length_items_decode_and_a_stray_break_does_not():
    import pytest

    from poaw_core import nitro as N

    assert N.cbor_decode(bytes.fromhex("bf616101616202ff")) == {"a": 1, "b": 2}
    assert N.cbor_decode(bytes.fromhex("9f0102ff")) == [1, 2]
    assert N.cbor_decode(bytes.fromhex("5f4201024103ff")) == b"\x01\x02\x03"
    for bad in ("bf6161", "ff", "bf616101616101ff", "5f6161ff"):  # no break, lone break, duplicate key, mixed chunk
        with pytest.raises(ValueError):
            N.cbor_decode(bytes.fromhex(bad))
