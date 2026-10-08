"""§8.4 anchor checking against a fake chain: every mismatch fails, and only a fully matching attestation passes."""
import sys
from pathlib import Path

import pytest
from eth_abi import encode

sys.path.insert(0, str(Path(__file__).parents[1] / "tools"))
sys.path.insert(0, str(Path(__file__).parents[2] / "core-python" / "src"))
import anchor_check as A  # noqa: E402
import poaw_core as p  # noqa: E402

ATTESTER = "0x23a848B41db0f152b7B9811e8314B6531dFAe523"
SCHEMA = b"\x5c" * 32
LOG = p.sha256(b"log")
ROOT = p.sha256(b"root")
UID = b"\x77" * 32


def chain(*, chain_id=84532, uid=UID, schema=SCHEMA, attester=ATTESTER, revoked=0, time_=1790000000, log=LOG, size=9, root=ROOT):
    data = encode(A._DATA, [log, size, root, 5, b"\x00" * 32, "poaw/0.1"])
    att = encode([A._ATT], [(uid, schema, time_, 0, revoked, b"\x00" * 32, "0x" + "00" * 20, attester, False, data)])

    def rpc(url, method, *params):
        return hex(chain_id) if method == "eth_chainId" else "0x" + att.hex()
    return rpc


PROOF = {"log_id": p.b64u(LOG), "leaf_index": 0, "tree_size": 9, "root_hash": p.b64u(ROOT),
         "anchor": {"chain": "eip155:84532", "scheme": "eas", "uid": "0x" + UID.hex(), "tx_hash": "0x" + "11" * 32, "tree_size": 9}}
KEYS = {"anchor_addresses": [ATTESTER], "anchor_schemas": ["0x" + SCHEMA.hex()]}


def run(monkeypatch, rpc, proof=PROOF, keys=KEYS):
    monkeypatch.setattr(A, "_rpc", rpc)
    return A.check_anchor(proof, keys, "http://rpc", p.b64u_decode)


def test_matching_attestation_is_anchored_with_proven_by(monkeypatch):
    r = run(monkeypatch, chain())
    assert r == {"ok": True, "reason": "anchored", "proven_by": 1790000000}


@pytest.mark.parametrize("kw,reason", [
    ({"chain_id": 8453}, "rpc_chain_mismatch"),
    ({"uid": b"\x00" * 32, "time_": 0}, "attestation_not_found"),
    ({"revoked": 1790000001}, "attestation_revoked"),
    ({"attester": "0x" + "12" * 20}, "attester_not_published"),
    ({"schema": b"\x01" * 32}, "schema_not_published"),
    ({"log": p.sha256(b"other log")}, "log_or_size_mismatch"),
    ({"size": 10}, "log_or_size_mismatch"),
    ({"root": p.sha256(b"forged")}, "root_mismatch"),
])
def test_every_mismatch_fails(monkeypatch, kw, reason):
    r = run(monkeypatch, chain(**kw))
    assert r["ok"] is False and r["reason"] == reason and r["proven_by"] is None


def test_rpc_failure_is_unproven_not_proven(monkeypatch):
    def boom(*a):
        raise OSError("network down")
    assert run(monkeypatch, boom)["reason"] == "unreadable:OSError"


def test_differing_sizes_without_consistency_proof_fail(monkeypatch):
    proof = {**PROOF, "tree_size": 12}
    assert run(monkeypatch, chain(), proof)["reason"] == "consistency_proof_required"
