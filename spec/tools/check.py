# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=43", "rfc8785==0.1.4", "jsonschema>=4.23", "eth-abi>=5", "eth-hash[pycryptodome]>=0.7"]
# ///
"""Reference checker for PoAW receipts and change entries (SPEC.md §10, §14). Offline it checks steps 1–4 and 7. With --rpc
it also checks the anchor against the chain (§8.4). With --pipeline it checks the receipt's `policy` against the pipeline
document (§15.2). Usage: uv run check.py <entry.json> <keys.json> [--rpc https://sepolia.base.org] [--pipeline pipeline.json]"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

import jsonschema

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[2] / "core-python" / "src"))
import poaw_core as ref  # noqa: E402

_SCHEMAS = Path(__file__).parents[1] / "schema"
_VALIDATOR = jsonschema.Draft202012Validator(json.loads((_SCHEMAS / "receipt.schema.json").read_text()))
_CHANGE_VALIDATOR = jsonschema.Draft202012Validator(json.loads((_SCHEMAS / "change.schema.json").read_text()))
_PIPELINE_VALIDATOR = jsonschema.Draft202012Validator(json.loads((_SCHEMAS / "pipeline.schema.json").read_text()))


def check_policy(policy: dict, pipeline: dict) -> bool:
    """SPEC §15.2: the document is valid, its id and version are the policy's, and its digest is the policy's."""
    return bool(
        isinstance(pipeline, dict)
        and not ref.has_float(pipeline)
        and not list(_PIPELINE_VALIDATOR.iter_errors(pipeline))
        and pipeline.get("id") == policy.get("pipeline_id")
        and pipeline.get("version") == policy.get("pipeline_version")
        and ref.pipeline_digest(pipeline) == policy.get("digest")
    )


def fetch_json(url: str) -> dict:
    """GET a JSON document (the issuer's public log endpoints need no auth, §8.6)."""
    req = urllib.request.Request(url, headers={"accept": "application/json", "user-agent": "poaw-check/0.1"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def _key_valid(key: dict | None, key_id: str, issued: str) -> bool:
    return bool(
        key
        and key.get("key_id") == key_id
        and ref.key_id(ref.b64u_decode(key["public_key"])) == key["key_id"]
        and key["valid_from"] <= issued
        and (key.get("revoked_at") is None or issued < key["revoked_at"])
    )


def check_tree_head(head: dict, keyset: dict) -> dict:
    """SPEC §8.5: exactly the four body fields with an integer tree_size, a key valid at `issued_at`, and a signature under
    the tree-head domain. Returns {"checks": {"shape","key","signature"}, "valid"}."""
    body = head.get("body") if isinstance(head, dict) else None
    sig = head.get("signature") if isinstance(head, dict) else None
    sig = sig if isinstance(sig, dict) else {}
    shape = (isinstance(body, dict) and set(body) == set(ref.TREE_HEAD_FIELDS)
             and isinstance(body["tree_size"], int) and not isinstance(body["tree_size"], bool) and body["tree_size"] >= 0
             and all(isinstance(body[k], str) for k in ("log_id", "root_hash", "issued_at"))
             and sig.get("alg") == "Ed25519")
    key = next((k for k in keyset.get("keys", []) if k.get("key_id") == sig.get("key_id")), None)
    try:
        key_ok = bool(shape and _key_valid(key, sig.get("key_id"), body["issued_at"]))
        sig_ok = bool(key_ok and ref.verify_tree_head(ref.b64u_decode(key["public_key"]), body, sig.get("value", "")))
    except Exception:  # undecodable key or signature: unproven, never a pass
        key_ok = sig_ok = False
    return {"checks": {"shape": shape, "key": key_ok, "signature": sig_ok}, "valid": bool(shape and key_ok and sig_ok)}


def make_consistency_source(supplied: list[dict] | None = None, issuer: str | None = None, fetch=None):
    """Return get(first, second) -> consistency document | None: a supplied document for those sizes, else the issuer's
    GET /v1/log/consistency, else None (the caller reports `consistency_proof_required`)."""
    supplied = list(supplied or [])
    fetch = fetch or fetch_json

    def get(first: int, second: int):
        for d in supplied:
            if isinstance(d, dict) and d.get("first") == first and d.get("second") == second:
                return d
        if issuer:
            try:
                return fetch(f"{issuer.rstrip('/')}/v1/log/consistency?first={first}&second={second}")
            except Exception:
                return None
        return None
    return get


def check_head(head_doc: dict, proof: dict | None, keyset: dict, get_consistency) -> dict:
    """SPEC §8.5 + §8.4: the head's signature verifies, and (when the receipt has a proof) the receipt's tree is a prefix
    of the head's. `head_doc` is a bare {body, signature} or the /v1/log/head response."""
    head = head_doc.get("tree_head", head_doc) if isinstance(head_doc, dict) else {}
    r = check_tree_head(head, keyset)
    if not r["valid"]:
        return {"ok": False, "reason": "head_signature_invalid", "checks": r["checks"]}
    hb = head["body"]
    if proof is None:
        return {"ok": True, "reason": "head_signed", "checks": r["checks"]}
    if hb["log_id"] != proof["log_id"]:
        return {"ok": False, "reason": "log_mismatch", "checks": r["checks"]}
    m, n = proof["tree_size"], hb["tree_size"]
    if m > n:
        return {"ok": False, "reason": "head_older_than_receipt", "checks": r["checks"]}
    if m == n:
        return {"ok": hb["root_hash"] == proof["root_hash"], "reason": "head_consistent" if hb["root_hash"] == proof["root_hash"] else "root_mismatch", "checks": r["checks"]}
    doc = get_consistency(m, n)
    if doc is None:
        return {"ok": False, "reason": "consistency_proof_required", "checks": r["checks"]}
    from anchor_check import check_consistency  # lazy: it pulls in the chain libraries, which offline checks don't need
    ok = check_consistency(doc, m, n, proof["root_hash"], hb["root_hash"])
    return {"ok": ok, "reason": "head_consistent" if ok else "not_consistent", "checks": r["checks"]}


def check(receipt: dict, keyset: dict, rpc_url: str | None = None, pipeline: dict | None = None, *,
          head: dict | None = None, consistency: list[dict] | None = None, issuer: str | None = None, fetch=None) -> dict:
    """Return a report for a receipt or a change entry. `valid` is true only if every check that applies passes."""
    report: dict = {"checks": {}}
    c = report["checks"]

    body = receipt.get("body", {}) if isinstance(receipt, dict) else {}
    kind = ref.entry_kind(body)
    is_change = kind == "change"
    version = str(body.get("spec_version", ""))
    c["spec_version"] = version.split("/")[0] == "poaw" and version.split("/")[-1].split(".")[0] == "0"
    # §14: no entry_kind is a receipt, "change" is a change entry, anything else is not an entry this spec defines.
    validator = _CHANGE_VALIDATOR if is_change else _VALIDATOR
    c["schema"] = (kind is None or is_change) and not list(validator.iter_errors(receipt))
    c["integers_only"] = not ref.has_float(receipt)

    sig = receipt.get("signature", {}) if isinstance(receipt, dict) else {}
    key = next((k for k in keyset.get("keys", []) if k["key_id"] == sig.get("key_id")), None)
    issued = body.get("issued_at", "")
    key_ok = bool(
        key
        and sig.get("key_id") == body.get("issuer", {}).get("key_id")
        and ref.key_id(ref.b64u_decode(key["public_key"])) == key["key_id"]
        and key["valid_from"] <= issued
        and (key.get("revoked_at") is None or issued < key["revoked_at"])
    )
    c["key"] = key_ok
    domain = ref.CHANGE_SIG_DOMAIN if is_change else ref.SIG_DOMAIN
    c["signature"] = bool(
        key_ok and ref.verify_signature(ref.b64u_decode(key["public_key"]), body, sig.get("value", ""), domain))
    if not is_change:  # a change entry has no claim (§14.1)
        claim = body.get("claim", {})
        c["claim_digest"] = isinstance(claim, dict) and claim.get("claim_digest") == ref.claim_digest(claim)

    proof = receipt.get("proof")
    get_consistency = make_consistency_source(consistency, issuer, fetch)
    if proof is None:
        c["inclusion"] = "absent"
    else:
        root = ref.root_from_inclusion(
            proof["leaf_index"], proof["tree_size"], ref.leaf_hash(receipt),
            [ref.b64u_decode(h) for h in proof["inclusion"]],
        )
        c["inclusion"] = root is not None and ref.b64u(root) == proof["root_hash"]
    if not (proof and proof.get("anchor")):
        c["anchor"] = "absent"
    elif not rpc_url:
        c["anchor"] = "not_checked_offline"
    else:
        from anchor_check import check_anchor
        a = check_anchor(proof, keyset, rpc_url, ref.b64u_decode, get_consistency)
        c["anchor"] = True if a["ok"] else a["reason"]
        report["proven_by"] = a["proven_by"]
    if head is not None:  # §8.5: only when the caller supplied a signed tree head
        h = check_head(head, proof, keyset, get_consistency)
        c["head"] = True if h["ok"] else h["reason"]

    # §15.2: only present when the body carries a policy. Without the pipeline document it is "not_checked".
    policy = body.get("policy")
    if policy is not None:
        c["policy"] = "not_checked" if pipeline is None else (isinstance(policy, dict) and check_policy(policy, pipeline))
    if is_change:
        report["entry_kind"] = "change"

    required = ("spec_version", "schema", "integers_only", "key", "signature") + (() if is_change else ("claim_digest",))
    report["valid"] = (all(c[k] is True for k in required) and c["inclusion"] in (True, "absent")
                       and c.get("policy", True) in (True, "not_checked") and c.get("head", True) is True)
    # §7: report the ACHIEVED level. L2 needs inclusion AND an anchor verified on-chain (--rpc); offline the ceiling is 1.
    report["achieved_trust_level"] = (2 if c["inclusion"] is True and c["anchor"] is True else 1) if report["valid"] else 0
    report["verdict"] = body.get("verdict", {}).get("value") if report["valid"] and not is_change else None
    return report


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("receipt"); ap.add_argument("keys"); ap.add_argument("--rpc"); ap.add_argument("--pipeline")
    ap.add_argument("--consistency", action="append", default=[], metavar="FILE", help="a /v1/log/consistency response (repeatable)")
    ap.add_argument("--head", metavar="FILE|URL", help="a signed tree head (§8.5): a file or the issuer's /v1/log/head URL")
    ap.add_argument("--issuer", metavar="URL", help="issuer base URL, to fetch consistency proofs when none is supplied")
    args = ap.parse_args()
    receipt = json.loads(Path(args.receipt).read_text())
    keyset = json.loads(Path(args.keys).read_text())
    pipeline = json.loads(Path(args.pipeline).read_text()) if args.pipeline else None
    issuer = args.issuer
    head = None
    if args.head:
        if args.head.startswith(("http://", "https://")):
            head = fetch_json(args.head)
            if not issuer and args.head.rstrip("/").endswith("/v1/log/head"):
                issuer = args.head.rstrip("/")[: -len("/v1/log/head")]
        else:
            head = json.loads(Path(args.head).read_text())
    consistency = [json.loads(Path(f).read_text()) for f in args.consistency]
    print(json.dumps(check(receipt, keyset, args.rpc, pipeline, head=head, consistency=consistency, issuer=issuer), indent=2))
