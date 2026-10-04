"""SPEC §8.5 signed tree head: valid, tampered, extra field, and never valid under another domain."""
import poaw_core as p
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SK = Ed25519PrivateKey.generate()
PK = p.public_key_bytes(SK)
ROOT = p.sha256(b"root")


def head(size=7):
    body = p.tree_head_body("log-1", size, ROOT, "2026-10-04T12:00:00.000Z")
    return body, p.sign_tree_head(SK, body)


def test_valid_head_verifies():
    body, sig = head()
    assert sig["alg"] == "Ed25519" and sig["key_id"] == p.key_id(PK)
    assert body == {"log_id": "log-1", "tree_size": 7, "root_hash": p.b64u(ROOT), "issued_at": "2026-10-04T12:00:00.000Z"}
    assert p.verify_tree_head(PK, body, sig["value"])


def test_empty_log_head_verifies():
    body, sig = head(0)
    assert p.verify_tree_head(PK, body, sig["value"])


def test_tampered_fields_rejected():
    body, sig = head()
    assert not p.verify_tree_head(PK, {**body, "tree_size": 8}, sig["value"])
    assert not p.verify_tree_head(PK, {**body, "root_hash": p.b64u(p.sha256(b"x"))}, sig["value"])
    assert not p.verify_tree_head(PK, {**body, "log_id": "other"}, sig["value"])
    assert not p.verify_tree_head(p.public_key_bytes(Ed25519PrivateKey.generate()), body, sig["value"])


def test_extra_or_missing_field_rejected_even_if_signed():
    body, _ = head()
    extra = {**body, "note": "x"}
    assert not p.verify_tree_head(PK, extra, p.sign_tree_head(SK, extra)["value"])
    short = {k: v for k, v in body.items() if k != "issued_at"}
    assert not p.verify_tree_head(PK, short, p.sign_tree_head(SK, short)["value"])


def test_bad_size_types_rejected():
    body, _ = head()
    for bad in (True, "7", -1, 7.0):
        b = {**body, "tree_size": bad}
        assert not p.verify_tree_head(PK, b, p.sign_tree_head(SK, b)["value"])


def test_head_signature_is_not_a_receipt_or_change_signature():
    body, sig = head()
    assert not p.verify_signature(PK, body, sig["value"])  # receipt domain
    assert not p.verify_change_signature(PK, body, sig["value"])
    receipt_sig = p.sign_body(SK, body)  # a receipt-domain signature over the same bytes is no tree head
    assert not p.verify_tree_head(PK, body, receipt_sig["value"])
