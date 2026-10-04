"""§8.4–§8.5: signed tree heads and consistency proofs. The manifest vectors, then check.py end to end: --head, and an anchor
whose size differs from the receipt's (in both directions) verified with a consistency proof instead of being refused."""
import copy
import json
import sys
from pathlib import Path

import pytest
from eth_abi import encode

TOOLS = Path(__file__).parents[1] / "tools"
VECTORS = Path(__file__).parents[1] / "vectors"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(Path(__file__).parents[2] / "core-python" / "src"))
import anchor_check as A  # noqa: E402
import check as C  # noqa: E402
import poaw_core as p  # noqa: E402

MANIFEST = json.loads((VECTORS / "manifest.json").read_text())
KEYS = json.loads((VECTORS / MANIFEST["keyset"]).read_text())


def load(name):
    return json.loads((VECTORS / name).read_text())


@pytest.mark.parametrize("entry", MANIFEST["tree_head_vectors"], ids=lambda e: e["file"])
def test_tree_head_vector(entry):
    r = C.check_tree_head(load(entry["file"]), KEYS)
    assert {"valid": r["valid"], "checks": r["checks"]} == entry["expected"], entry["description"]


@pytest.mark.parametrize("entry", MANIFEST["consistency_vectors"], ids=lambda e: e["file"])
def test_consistency_vector(entry):
    d = load(entry["file"])
    got = p.verify_consistency(d["first"], d["second"], p.b64u_decode(d["first_root"]), p.b64u_decode(d["second_root"]),
                               [p.b64u_decode(h) for h in d["proof"]])
    assert got is entry["expected"]["valid"], entry["description"]


def test_vector_counts():
    assert (len(MANIFEST["vectors"]), len(MANIFEST["tree_head_vectors"]), len(MANIFEST["consistency_vectors"])) == (35, 4, 2)


# --- check.py with a log of 9 leaves; the receipt is leaf 2 proven at size 6 ----------------------------------------------
LOG_ID = p.b64u(p.sha256(b"example-log"))
RECEIPTS = [{"body": {"n": i}, "signature": {"value": str(i)}} for i in range(9)]
LEAVES = [p.leaf_hash(r) for r in RECEIPTS]


def root(n):
    return p.mth(LEAVES[:n])


def cdoc(m, n):
    return {"log_id": LOG_ID, "first": m, "second": n, "first_root": p.b64u(root(m)), "second_root": p.b64u(root(n)),
            "proof": [p.b64u(h) for h in p.consistency_proof(m, n, LEAVES)]}


def proof_at(size, anchor_size=None):
    pr = {"log_id": LOG_ID, "leaf_index": 2, "tree_size": size, "root_hash": p.b64u(root(size)),
          "inclusion": [p.b64u(h) for h in p.inclusion_path(2, LEAVES[:size])]}
    if anchor_size:
        pr["anchor"] = {"chain": "eip155:84532", "scheme": "eas", "uid": "0x" + "77" * 32, "tx_hash": "0x" + "11" * 32, "tree_size": anchor_size}
    return pr


def signed_head(size, key_hex=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex or "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))  # gitleaks:allow (RFC 8032 public test key)
    b = p.tree_head_body(LOG_ID, size, root(size), "2026-09-25T14:05:00.000Z")
    return {"body": b, "signature": p.sign_tree_head(sk, b)}


def test_head_proves_receipt_tree_is_a_prefix():
    pr = proof_at(6)
    get = C.make_consistency_source([cdoc(6, 9)])
    assert C.check_head(signed_head(9), pr, KEYS, get)["ok"] is True
    assert C.check_head({"tree_head": signed_head(9), "anchor": None}, pr, KEYS, get)["ok"] is True  # /v1/log/head shape


def test_head_without_a_consistency_proof_is_unproven():
    r = C.check_head(signed_head(9), proof_at(6), KEYS, C.make_consistency_source())
    assert r["ok"] is False and r["reason"] == "consistency_proof_required"


def test_head_fetches_the_proof_from_the_issuer():
    seen = []

    def fetch(url):
        seen.append(url)
        return cdoc(6, 9)
    get = C.make_consistency_source(issuer="https://api.example.test/", fetch=fetch)
    assert C.check_head(signed_head(9), proof_at(6), KEYS, get)["ok"] is True
    assert seen == ["https://api.example.test/v1/log/consistency?first=6&second=9"]


def test_head_with_a_forked_history_fails():
    pr = proof_at(6)
    bad = cdoc(6, 9)
    bad["proof"][0] = p.b64u(p.sha256(b"forged"))
    r = C.check_head(signed_head(9), pr, KEYS, C.make_consistency_source([bad]))
    assert r["ok"] is False and r["reason"] == "not_consistent"


def test_head_older_than_the_receipt_fails_and_equal_size_needs_equal_roots():
    assert C.check_head(signed_head(4), proof_at(6), KEYS, C.make_consistency_source())["reason"] == "head_older_than_receipt"
    assert C.check_head(signed_head(6), proof_at(6), KEYS, C.make_consistency_source())["ok"] is True


def test_head_signed_by_an_unknown_key_fails():
    r = C.check_head(signed_head(9, "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"), proof_at(6), KEYS,
                     C.make_consistency_source([cdoc(6, 9)]))
    assert r["ok"] is False  # key B was revoked before the head's issued_at


def test_check_report_marks_head_and_requires_it_to_pass():
    receipt = load("016-inclusion-first-leaf.json")
    good = C.check(receipt, KEYS, head=signed_head(7))
    # the vector's own log differs from the 9-leaf test log, so the head can't be a descendant: the report must say so
    assert good["checks"]["head"] is not True and good["valid"] is False
    assert "head" not in C.check(receipt, KEYS)["checks"]


# --- anchor with a size different from the receipt's ---------------------------------------------------------------------
ATTESTER = "0x23a848B41db0f152b7B9811e8314B6531dFAe523"
SCHEMA = b"\x5c" * 32
UID = b"\x77" * 32
ANCH_KEYS = {"anchor_addresses": [ATTESTER], "anchor_schemas": ["0x" + SCHEMA.hex()]}


def chain(size, *, root_bytes=None):
    data = encode(A._DATA, [p.b64u_decode(LOG_ID), size, root_bytes if root_bytes is not None else root(size), 0, b"\x00" * 32, "poaw/0.1"])
    att = encode([A._ATT], [(UID, SCHEMA, 1790000000, 0, 0, b"\x00" * 32, "0x" + "00" * 20, ATTESTER, False, data)])
    return lambda url, method, *a: hex(84532) if method == "eth_chainId" else "0x" + att.hex()


def anchor(monkeypatch, proof, rpc, doc):
    monkeypatch.setattr(A, "_rpc", rpc)
    get = (lambda m, n: doc) if doc is not None else None
    return A.check_anchor(proof, ANCH_KEYS, "http://rpc", p.b64u_decode, get)


@pytest.mark.parametrize("proof_size,anchor_size", [(6, 9), (9, 6), (4, 8)])
def test_anchor_at_a_different_size_verifies_with_a_consistency_proof(monkeypatch, proof_size, anchor_size):
    m, n = sorted((proof_size, anchor_size))
    r = anchor(monkeypatch, proof_at(proof_size, anchor_size), chain(anchor_size), cdoc(m, n))
    assert r == {"ok": True, "reason": "anchored", "proven_by": 1790000000}


def test_anchor_at_a_different_size_without_a_proof_is_still_refused(monkeypatch):
    r = anchor(monkeypatch, proof_at(6, 9), chain(9), None)
    assert r["reason"] == "consistency_proof_required"


def test_anchor_consistency_failures(monkeypatch):
    bad = cdoc(6, 9)
    bad["proof"][-1] = p.b64u(p.sha256(b"forged"))
    assert anchor(monkeypatch, proof_at(6, 9), chain(9), bad)["reason"] == "consistency_proof_invalid"
    # the chain attests a different root at size 9: the (honest) proof no longer connects it to the receipt's tree
    assert anchor(monkeypatch, proof_at(6, 9), chain(9, root_bytes=p.sha256(b"forked")), cdoc(6, 9))["reason"] == "consistency_proof_invalid"
    # a proof for other sizes is not a proof for these
    assert anchor(monkeypatch, proof_at(6, 9), chain(9), cdoc(6, 8))["reason"] == "consistency_proof_invalid"
    wrong_receipt = copy.deepcopy(proof_at(6, 9))
    wrong_receipt["root_hash"] = p.b64u(p.sha256(b"x"))
    assert anchor(monkeypatch, wrong_receipt, chain(9), cdoc(6, 9))["reason"] == "consistency_proof_invalid"
