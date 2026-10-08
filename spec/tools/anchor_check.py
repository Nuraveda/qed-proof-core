"""SPEC §8.4: check a receipt's `proof.anchor` (scheme `eas`) against a public JSON-RPC endpoint. It needs no issuer API.

It needs only the chain (plus, when the anchored size differs from the receipt's, an RFC 6962 consistency proof the caller
supplies or fetches from the issuer): EAS.getAttestation(uid) must be a live, unrevoked attestation made by an address the issuer
publishes, under a schema the issuer publishes, whose data decodes to this proof's (log_id, tree_size, root_hash).
"""
from __future__ import annotations

import json
import urllib.request

from eth_abi import decode as abi_decode
from eth_hash.auto import keccak

EAS = "0x4200000000000000000000000000000000000021"  # the OP-stack predeploy (Base mainnet + Base Sepolia)
_GET = keccak(b"getAttestation(bytes32)")[:4]
_ATT = "(bytes32,bytes32,uint64,uint64,uint64,bytes32,address,address,bool,bytes)"
_DATA = ["bytes32", "uint64", "bytes32", "uint64", "bytes32", "string"]


def _rpc(url: str, method: str, *params):
    req = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode(),
                                 {"content-type": "application/json", "user-agent": "poaw-check/0.1"})
    with urllib.request.urlopen(req, timeout=20) as r:
        body = json.loads(r.read())
    if "error" in body:
        raise RuntimeError(f"{method}: {body['error'].get('message')}")
    return body["result"]


def check_consistency(doc: dict, first: int, second: int, old_root: str, new_root: str) -> bool:
    """SPEC §8.4: `doc` (shaped like GET /v1/log/consistency) proves the size-`first` tree with root `old_root` is a prefix of
    the size-`second` tree with root `new_root`. The roots come from the caller's own trusted sources, never from `doc`."""
    import poaw_core as ref
    try:
        if not isinstance(doc, dict) or doc.get("first") != first or doc.get("second") != second:
            return False
        proof = [ref.b64u_decode(h) for h in doc["proof"]]
        return ref.verify_consistency(first, second, ref.b64u_decode(old_root), ref.b64u_decode(new_root), proof)
    except Exception:
        return False


def check_anchor(proof: dict, keyset: dict, rpc_url: str, b64u_decode, get_consistency=None) -> dict:
    """`get_consistency(first, second)` returns a consistency document (shaped like GET /v1/log/consistency) or None; it is
    only consulted when the anchor's size differs from the proof's. Return {"ok": bool, "reason": str, "proven_by": unix seconds | None}. Any doubt → ok False, never a pass."""
    a = proof["anchor"]
    try:
        if a.get("scheme") != "eas":
            return {"ok": False, "reason": "unknown_scheme", "proven_by": None}
        if int(_rpc(rpc_url, "eth_chainId"), 16) != int(str(a["chain"]).split(":")[1]):
            return {"ok": False, "reason": "rpc_chain_mismatch", "proven_by": None}
        uid = bytes.fromhex(a["uid"][2:])
        out = _rpc(rpc_url, "eth_call", {"to": EAS, "data": "0x" + (_GET + uid).hex()}, "latest")
        (att,) = abi_decode([_ATT], bytes.fromhex(out[2:]))
        uid_, schema, time_, _exp, revoked_at, _ref, _recipient, attester, _revocable, data = att
    except Exception as exc:  # network, decode or shape errors: the anchor is unproven, not proven
        return {"ok": False, "reason": f"unreadable:{type(exc).__name__}", "proven_by": None}
    if uid_ != uid or time_ == 0:
        return {"ok": False, "reason": "attestation_not_found", "proven_by": None}
    if revoked_at:
        return {"ok": False, "reason": "attestation_revoked", "proven_by": None}
    if attester.lower() not in {x.lower() for x in keyset.get("anchor_addresses", [])}:
        return {"ok": False, "reason": "attester_not_published", "proven_by": None}
    if "0x" + schema.hex() not in {x.lower() for x in keyset.get("anchor_schemas", [])}:
        return {"ok": False, "reason": "schema_not_published", "proven_by": None}
    try:
        log_id, size, root, _prev_size, _prev_root, _spec = abi_decode(_DATA, data)
    except Exception:
        return {"ok": False, "reason": "data_undecodable", "proven_by": None}
    if log_id != b64u_decode(proof["log_id"]) or size != a["tree_size"]:
        return {"ok": False, "reason": "log_or_size_mismatch", "proven_by": None}
    leaf = proof.get("leaf_index")
    if a["tree_size"] < proof["tree_size"] and not (isinstance(leaf, int) and 0 <= leaf < a["tree_size"]):
        # §8.4: an anchor of a smaller tree only covers its own leaves. A consistency proof shows the receipt's tree extends
        # the anchored one; it says nothing about a leaf appended after it, so that leaf gets no proven-by time from it.
        return {"ok": False, "reason": "anchor_does_not_cover_leaf", "proven_by": None}
    if a["tree_size"] != proof["tree_size"]:
        # §8.4: connect the two roots with an RFC 6962 consistency proof. The anchored root is the chain's (`root`); the
        # receipt's is `proof.root_hash`. Whichever tree is smaller is the "old" one; the larger must extend it.
        doc = get_consistency(*sorted((a["tree_size"], proof["tree_size"]))) if get_consistency else None
        if doc is None:
            return {"ok": False, "reason": "consistency_proof_required", "proven_by": None}
        import poaw_core as ref
        chain_root, proof_root = ref.b64u(root), proof["root_hash"]
        if a["tree_size"] < proof["tree_size"]:
            ok = check_consistency(doc, a["tree_size"], proof["tree_size"], chain_root, proof_root)
        else:
            ok = check_consistency(doc, proof["tree_size"], a["tree_size"], proof_root, chain_root)
        if not ok:
            return {"ok": False, "reason": "consistency_proof_invalid", "proven_by": None}
        return {"ok": True, "reason": "anchored", "proven_by": time_}
    if root != b64u_decode(proof["root_hash"]):
        return {"ok": False, "reason": "root_mismatch", "proven_by": None}
    return {"ok": True, "reason": "anchored", "proven_by": time_}  # EAS sets time = block.timestamp
