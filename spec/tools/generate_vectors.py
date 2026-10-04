# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=43", "rfc8785==0.1.4", "jsonschema>=4.23"]
# ///
"""Generate the PoAW conformance vectors (SPEC.md §13) deterministically. 001–020 are poaw/0.1 and must never change (a
checker that reads them today reads them tomorrow); 021 onward cover poaw/0.2 (policy, change entries).

    uv run oss/spec/tools/generate_vectors.py            # write vectors/
    uv run oss/spec/tools/generate_vectors.py --check    # fail if vectors/ differs (CI)

The signing keys are the PUBLIC test keys from RFC 8032 §7.1 (tests 1 and 2). They are test-only
and must never sign a real receipt.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[2] / "core-python" / "src"))
import poaw_core as ref  # noqa: E402
from check import check, check_tree_head  # noqa: E402

OUT = Path(__file__).parents[1] / "vectors"

# RFC 8032 §7.1 TEST 1 and TEST 2 secret keys (published test material).
KEY_A = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))  # gitleaks:allow (RFC 8032 public test key)
KEY_B = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))  # gitleaks:allow (RFC 8032 public test key)
KID_A, KID_B = (ref.key_id(ref.public_key_bytes(k)) for k in (KEY_A, KEY_B))
KEY_B_REVOKED_AT = "2026-06-01T00:00:00.000Z"

KEYSET = {
    "keys": [
        {"key_id": KID_A, "public_key": ref.b64u(ref.public_key_bytes(KEY_A)), "valid_from": "2026-01-01T00:00:00.000Z", "revoked_at": None},
        {"key_id": KID_B, "public_key": ref.b64u(ref.public_key_bytes(KEY_B)), "valid_from": "2026-01-01T00:00:00.000Z", "revoked_at": KEY_B_REVOKED_AT},
    ]
}

FP_POST = "sha256:" + ref.b64u(ref.sha256(b"Shipping receipts for agents today."))
FP_OTHER = "sha256:" + ref.b64u(ref.sha256(b"A different post."))


def claim(action: str, target: str, params: dict, n: int) -> dict:
    c = {"action": action, "target": target, "params": params,
         "claimed_at": "2026-09-25T14:01:58.000Z", "client_claim_id": f"example-{n:03d}"}
    c["claim_digest"] = ref.claim_digest(c)
    return c


def body(n: int, verdict: dict, *, kid: str = KID_A, issued_at: str = "2026-09-25T14:02:12.000Z",
         action: str = "x.post.publish", facts: dict | None = None, trust_level: int = 1) -> dict:
    return {
        "spec_version": ref.SPEC_VERSION,
        "receipt_id": f"rcpt_01J8Z6Q4W3EXAMPLE{n:06d}",
        "issued_at": issued_at,
        "issuer": {"key_id": kid, "name": "example-issuer"},
        "agent": {"id": "agent-example-1"},
        "claim": claim(action, "x.com/example", {"content_fingerprint": FP_POST}, n),
        "observation": {
            "verifier": {"id": action, "version": "1"},
            "observed_at": "2026-09-25T14:02:11.000Z",
            "deadline_at": "2026-09-25T14:17:58.000Z",
            "attempts": 1,
            "facts": facts if facts is not None else {"found": True, "post_id": "1840200000000000001", "content_fingerprint": FP_POST},
        },
        "verdict": verdict,
        "trust_level": trust_level,
    }


def signed(b: dict, key: Ed25519PrivateKey = KEY_A) -> dict:  # gitleaks:allow — a type annotation, not a secret
    return {"body": b, "signature": ref.sign_body(key, b)}


def signed_change(b: dict, key: Ed25519PrivateKey = KEY_A) -> dict:  # gitleaks:allow — a type annotation, not a secret
    return {"body": b, "signature": ref.sign_change(key, b)}


# A pipeline document used by the policy vectors (SPEC §15). Neutral on purpose: this file is published.
PIPELINE = {
    "schema": "pipeline/1", "id": "main-branch-pushes", "version": 2, "name": "Every push to main",
    "connector": {"provider": "github", "target": "example-org/example-repo"},
    "trigger": {"on": ["claim", "watch"], "watch": {"grace_seconds": 900}},
    "filter": {"all": [{"field": "event.branch", "op": "eq", "value": "main"}]},
    "check": {"profile": {"id": "github.commit.push", "version": "1"},
              "narrow": {"field": "observed.branch", "op": "eq", "value": "main"}},
    "outcomes": {"receipt": "always", "alerts": [{"on": ["mismatch", "failed", "unclaimed_change"], "channel": "email", "to": "ops@example.com"}]},
}
POLICY = {"pipeline_id": PIPELINE["id"], "pipeline_version": PIPELINE["version"], "digest": ref.pipeline_digest(PIPELINE)}


def body02(n: int, verdict: dict, **kw) -> dict:
    """A poaw/0.2 receipt body. `policy` (when given) is added; the version is 0.2 either way."""
    policy = kw.pop("policy", None)
    b = body(n, verdict, **kw)
    b["spec_version"] = ref.SPEC_VERSION_V02
    if policy is not None:
        b["policy"] = policy
    return b


def change_body(n: int, *, kid: str = KID_A, policy: dict | None = POLICY, issued_at: str = "2026-09-25T14:30:05.000Z") -> dict:
    b = {
        "spec_version": ref.SPEC_VERSION_V02,
        "entry_kind": "change",
        "change_id": f"chg_01J8Z6Q4W3EXAMPLE{n:06d}",
        "issued_at": issued_at,
        "issuer": {"key_id": kid, "name": "example-issuer"},
        "connector": "github",
        "event": "github.commit.push",
        "target": "example-org/example-repo",
        "fingerprint": "0123456789abcdef0123456789abcdef01234567",
        "seen_at": "2026-09-25T14:30:04.000Z",
        "occurred_at": "2026-09-25T14:14:50.000Z",
        "facts": {"branch": "main", "commit_found": True, "sha": "0123456789abcdef0123456789abcdef01234567"},
        "watcher": {"id": "github.commit.push", "version": "1"},
        "policy": policy,
        "trust_level": 1,
    }
    if policy is None:
        del b["policy"]
    return b


def build() -> list[tuple[str, str, dict, dict, dict | None]]:
    """(name, description, entry, expected, pipeline) — expected is filled from the reference checker and then
    asserted against the intent written here, so a checker bug can't silently redefine the vectors."""
    V: list[tuple[str, str, dict, dict, dict | None]] = []

    def add(name, desc, receipt, valid, verdict=None, pipeline=None, checks=None):
        V.append((name, desc, receipt, {"valid": valid, "verdict": verdict if valid else None, "checks": checks or {}}, pipeline))

    # --- valid receipts, one per verdict --------------------------------------------------------
    add("001-valid-verified", "Signed L1 receipt, verified.", signed(body(1, {"value": "verified"})), True, "verified")
    add("002-valid-late", "Outcome present but after tolerance.",
        signed(body(2, {"value": "late", "reason_code": "observed_after_tolerance"})), True, "late")
    add("003-valid-mismatch", "Post exists with a different fingerprint.",
        signed(body(3, {"value": "mismatch", "reason_code": "content_mismatch"},
                    facts={"found": True, "post_id": "1840200000000000003", "content_fingerprint": FP_OTHER})), True, "mismatch")
    add("004-valid-failed", "Destination read, outcome absent by deadline.",
        signed(body(4, {"value": "failed", "reason_code": "not_found"}, facts={"found": False})), True, "failed")
    add("005-valid-unverifiable", "Destination rate-limited until deadline.",
        signed(body(5, {"value": "unverifiable", "reason_code": "rate_limited"}, facts={})), True, "unverifiable")
    add("006-valid-key-b-before-revocation", "Key B, issued before its revocation: still valid.",
        signed(body(6, {"value": "verified"}, kid=KID_B, issued_at="2026-05-31T23:59:59.000Z"), KEY_B), True, "verified")

    # --- signature and key failures ---------------------------------------------------------------
    r = signed(body(7, {"value": "failed", "reason_code": "not_found"}))
    r["body"]["verdict"] = {"value": "verified"}  # altered after signing
    add("007-tampered-verdict", "Verdict changed from failed to verified after signing.", r, False)

    b = body(8, {"value": "verified"})  # claims key A…
    add("008-wrong-key", "Body names key A but was signed with key B.", {"body": b, "signature": {**ref.sign_body(KEY_B, b), "key_id": KID_A}}, False)

    b = body(9, {"value": "verified"}, kid="ed25519:" + ref.b64u(ref.sha256(b"unknown key")))
    s = ref.sign_body(KEY_A, b)
    add("009-unknown-key", "key_id not present in the issuer's key set.", {"body": b, "signature": {**s, "key_id": b["issuer"]["key_id"]}}, False)

    add("010-revoked-key", "Key B, issued after its revocation.",
        signed(body(10, {"value": "verified"}, kid=KID_B, issued_at="2026-09-25T14:02:12.000Z"), KEY_B), False)

    # --- structural failures ----------------------------------------------------------------------
    b = body(11, {"value": "verified"})
    b["claim"]["target"] = "x.com/someone-else"  # digest no longer matches (then re-signed, so only the digest fails)
    add("011-bad-claim-digest", "claim_digest does not match the claim.", signed(b), False)

    add("012-unverifiable-without-reason", "unverifiable MUST carry a reason_code (schema).",
        signed(body(12, {"value": "unverifiable"}, facts={})), False)
    add("013-level3-without-attestation", "trust_level 3 requires attestation + code_hash (schema).",
        signed(body(13, {"value": "verified"}, trust_level=3)), False)

    b = body(14, {"value": "verified"})
    b["observation"]["facts"]["score"] = 0.5
    add("014-float-in-body", "Floating-point numbers are not allowed (§3).", signed(b), False)

    b = body(15, {"value": "verified"})
    b["spec_version"] = "poaw/1.0"
    add("015-unsupported-major-version", "Unknown major spec_version must be rejected.", signed(b), False)

    # --- log inclusion (§8) -----------------------------------------------------------------------
    log = [signed(body(100 + i, {"value": "verified"}, trust_level=2)) for i in range(7)]
    leaves = [ref.leaf_hash(x) for x in log]
    root = ref.b64u(ref.mth(leaves))

    def with_proof(i: int) -> dict:
        x = copy.deepcopy(log[i])
        x["proof"] = {"log_id": ref.b64u(ref.sha256(b"example-log")), "leaf_index": i, "tree_size": len(log),
                      "root_hash": root, "inclusion": [ref.b64u(h) for h in ref.inclusion_path(i, leaves)]}
        return x

    add("016-inclusion-first-leaf", "Valid inclusion proof, leaf 0 of 7. Claims L2 but has no anchor: achieved level 1.", with_proof(0), True, "verified")
    add("017-inclusion-last-leaf", "Valid inclusion proof, leaf 6 of 7 (unbalanced edge).", with_proof(6), True, "verified")
    add("018-inclusion-middle-leaf", "Valid inclusion proof, leaf 3 of 7.", with_proof(3), True, "verified")
    x = with_proof(3)
    x["proof"]["inclusion"][0] = ref.b64u(ref.sha256(b"not a sibling"))
    add("019-bad-inclusion-path", "Altered audit path.", x, False)
    x = with_proof(3)
    x["proof"]["leaf_index"] = 4
    add("020-wrong-leaf-index", "Correct path, wrong index.", x, False)

    # === poaw/0.2 (SPEC §14–§16) ==================================================================
    add("021-valid-0.2-without-policy", "A poaw/0.2 receipt that uses nothing new is still a plain receipt.",
        signed(body02(21, {"value": "verified"})), True, "verified")
    add("022-valid-policy-checked", "Receipt with a policy, checked against the pipeline document: digest, id and version agree.",
        signed(body02(22, {"value": "verified"}, policy=POLICY)), True, "verified", pipeline=PIPELINE, checks={"policy": True})
    add("023-valid-policy-not-checked", "Same kind of receipt, but no pipeline document is available: policy is not_checked, and the receipt stays valid.",
        signed(body02(23, {"value": "verified"}, policy=POLICY)), True, "verified", checks={"policy": "not_checked"})
    add("024-policy-bad-digest", "The digest is not the digest of the pipeline document (a different document was substituted).",
        signed(body02(24, {"value": "verified"}, policy={**POLICY, "digest": ref.pipeline_digest({**PIPELINE, "name": "Something else"})})),
        False, pipeline=PIPELINE, checks={"policy": False})
    add("025-policy-version-mismatch", "The digest is right for the document, but the policy names a different version of it.",
        signed(body02(25, {"value": "verified"}, policy={**POLICY, "pipeline_version": 1})), False, pipeline=PIPELINE, checks={"policy": False})
    add("026-policy-on-0.1-body", "A policy is a 0.2 member: a body that says poaw/0.1 may not carry one (schema).",
        signed({**body(26, {"value": "verified"}), "policy": POLICY}), False, checks={"schema": False})

    # --- change entries (§14) ---------------------------------------------------------------------
    add("027-valid-change", "A change entry: an in-scope push nobody claimed. Same log, own signature domain, no verdict.",
        signed_change(change_body(27)), True, None, pipeline=PIPELINE, checks={"policy": True})
    x = signed_change(change_body(28))
    x["body"]["fingerprint"] = "ffffffffffffffffffffffffffffffffffffffff"  # altered after signing
    add("028-change-tampered", "The change's fingerprint was altered after signing.", x, False, checks={"signature": False})
    b = change_body(29)
    add("029-change-signed-as-receipt", "A change body signed under the receipt domain: the signature must not verify.",
        {"body": b, "signature": ref.sign_body(KEY_A, b)}, False, checks={"signature": False})
    b = body02(30, {"value": "verified"})
    add("030-receipt-signed-as-change", "A receipt signed under the change domain: the signature must not verify.",
        {"body": b, "signature": ref.sign_change(KEY_A, b)}, False, checks={"signature": False})
    add("031-change-without-policy", "A change entry MUST name the pipeline that was watching (schema).",
        signed_change(change_body(31, policy=None)), False, checks={"schema": False})
    b = change_body(32)
    b["claim"] = body(32, {"value": "verified"})["claim"]
    add("032-change-with-claim", "A change entry MUST NOT carry a claim (schema): there was none.", signed_change(b), False, checks={"schema": False})
    b = body02(33, {"value": "verified"})
    b["entry_kind"] = "banana"
    add("033-unknown-entry-kind", "An entry_kind this spec does not define is not an entry (schema).", signed(b), False, checks={"schema": False})

    # --- a log that holds both kinds (§8.1) ---------------------------------------------------------
    mixed = [signed(body02(200, {"value": "verified"}, trust_level=2)), signed_change(change_body(201)),
             signed(body02(202, {"value": "failed", "reason_code": "not_found"}, facts={"found": False}, trust_level=2)),
             signed_change(change_body(203)), signed(body02(204, {"value": "verified"}, trust_level=2))]
    mleaves = [ref.leaf_hash(e) for e in mixed]
    mroot = ref.b64u(ref.mth(mleaves))

    def mixed_proof(i: int) -> dict:
        e = copy.deepcopy(mixed[i])
        e["proof"] = {"log_id": ref.b64u(ref.sha256(b"example-log")), "leaf_index": i, "tree_size": len(mixed),
                      "root_hash": mroot, "inclusion": [ref.b64u(h) for h in ref.inclusion_path(i, mleaves)]}
        return e

    add("034-change-inclusion", "A change entry proven included in a log that also holds receipts (leaf 1 of 5).",
        mixed_proof(1), True, None, pipeline=PIPELINE, checks={"inclusion": True, "policy": True})
    x = mixed_proof(3)
    x["proof"]["inclusion"][0] = ref.b64u(ref.sha256(b"not a sibling"))
    add("035-change-bad-inclusion-path", "A change entry with an altered audit path.", x, False, pipeline=PIPELINE, checks={"inclusion": False})
    return V


def build_log() -> tuple[list[tuple[str, str, dict, dict]], list[tuple[str, str, dict, bool]]]:
    """Public-log vectors (SPEC §8.5, §8.4). Returns (tree heads, consistency proofs).
    Tree heads: (name, description, head, expected {valid, checks}). Consistency: (name, description, doc, valid)."""
    log_id = ref.b64u(ref.sha256(b"example-log"))
    leaves = [ref.leaf_hash(signed(body(300 + i, {"value": "verified"}, trust_level=2))) for i in range(7)]
    root7 = ref.mth(leaves)

    def head_body(size: int, root: bytes) -> dict:
        return ref.tree_head_body(log_id, size, root, "2026-09-25T14:05:00.000Z")

    def head(b: dict, key: Ed25519PrivateKey = KEY_A) -> dict:  # gitleaks:allow — a type annotation, not a secret
        return {"body": b, "signature": ref.sign_tree_head(key, b)}

    H: list[tuple[str, str, dict, dict]] = []
    ok = {"valid": True, "checks": {"shape": True, "key": True, "signature": True}}
    H.append(("036-tree-head-valid", "A signed tree head over the 7-leaf log of the inclusion vectors: valid.", head(head_body(7, root7)), ok))
    x = head(head_body(7, root7))
    x["body"]["tree_size"] = 8  # altered after signing
    H.append(("037-tree-head-tampered", "The tree_size was changed after signing.", x,
              {"valid": False, "checks": {"shape": True, "key": True, "signature": False}}))
    b = head_body(7, root7)
    H.append(("038-tree-head-signed-as-receipt", "A tree head body signed under the receipt domain: the signature must not verify.",
              {"body": b, "signature": ref.sign_body(KEY_A, b)}, {"valid": False, "checks": {"shape": True, "key": True, "signature": False}}))
    x = head(head_body(7, root7))
    x["body"]["extra"] = 1
    H.append(("039-tree-head-extra-field", "A body with a fifth field is not a tree head (§8.5: exactly four fields).", x,
              {"valid": False, "checks": {"shape": False, "key": False, "signature": False}}))

    def cdoc(m: int, n: int, *, old: bytes | None = None) -> dict:
        return {"log_id": log_id, "first": m, "second": n,
                "first_root": ref.b64u(old if old is not None else ref.mth(leaves[:m])), "second_root": ref.b64u(ref.mth(leaves[:n])),
                "proof": [ref.b64u(h) for h in ref.consistency_proof(m, n, leaves)]}

    C: list[tuple[str, str, dict, bool]] = [
        ("040-consistency-valid", "RFC 6962 consistency proof: the 3-leaf tree is a prefix of the 7-leaf tree.", cdoc(3, 7), True),
        ("041-consistency-wrong-old-root", "The same proof, but first_root is not the root of the first 3 leaves: must fail.",
         cdoc(3, 7, old=ref.sha256(b"not the old root")), False),
    ]
    return H, C


def main() -> int:
    vectors = build()
    files: dict[str, str] = {"keys.json": json.dumps(KEYSET, indent=2, sort_keys=True) + "\n"}
    manifest = []
    for name, desc, receipt, intent, pipeline in vectors:
        got = check(receipt, KEYSET, pipeline=pipeline)
        wrong = {k: (got["checks"].get(k), v) for k, v in intent["checks"].items() if got["checks"].get(k) != v}
        if got["valid"] != intent["valid"] or got["verdict"] != intent["verdict"] or wrong:
            print(f"reference checker disagrees with intent for {name}: {got} (check mismatches: {wrong})", file=sys.stderr)
            return 1
        files[f"{name}.json"] = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        entry = {"file": f"{name}.json", "description": desc, "expected": {
            "valid": got["valid"], "verdict": got["verdict"], "achieved_trust_level": got["achieved_trust_level"],
            "checks": got["checks"]}}
        if got.get("entry_kind"):
            entry["expected"]["entry_kind"] = got["entry_kind"]
        if pipeline is not None:
            entry["pipeline"] = "pipeline.example.json"  # the document the checker is given alongside the entry
        manifest.append(entry)
    heads, consistencies = build_log()
    head_manifest, consistency_manifest = [], []
    for name, desc, head, intent in heads:
        got = check_tree_head(head, KEYSET)
        if got["valid"] != intent["valid"] or got["checks"] != intent["checks"]:
            print(f"reference checker disagrees with intent for {name}: {got}", file=sys.stderr)
            return 1
        files[f"{name}.json"] = json.dumps(head, indent=2, sort_keys=True) + "\n"
        head_manifest.append({"file": f"{name}.json", "description": desc, "expected": {"valid": got["valid"], "checks": got["checks"]}})
    for name, desc, doc, intent_valid in consistencies:
        got = ref.verify_consistency(doc["first"], doc["second"], ref.b64u_decode(doc["first_root"]), ref.b64u_decode(doc["second_root"]),
                                     [ref.b64u_decode(h) for h in doc["proof"]])
        if got != intent_valid:
            print(f"reference checker disagrees with intent for {name}: {got}", file=sys.stderr)
            return 1
        files[f"{name}.json"] = json.dumps(doc, indent=2, sort_keys=True) + "\n"
        consistency_manifest.append({"file": f"{name}.json", "description": desc, "expected": {"valid": got}})
    files["pipeline.example.json"] = json.dumps(PIPELINE, indent=2, sort_keys=True) + "\n"
    files["manifest.json"] = json.dumps({"spec_version": ref.SPEC_VERSION_V02, "keyset": "keys.json", "vectors": manifest,
                                                  "tree_head_vectors": head_manifest, "consistency_vectors": consistency_manifest}, indent=2, sort_keys=True) + "\n"

    if "--check" in sys.argv:
        stale = [n for n, t in files.items() if not (OUT / n).exists() or (OUT / n).read_text() != t]
        extra = sorted({p.name for p in OUT.glob("*.json")} - set(files))
        if stale or extra:
            print(f"vectors out of date: stale={stale} extra={extra}", file=sys.stderr)
            return 1
        print(f"vectors up to date ({len(vectors)} vectors, {len(heads)} tree heads, {len(consistencies)} consistency proofs)")
        return 0
    OUT.mkdir(exist_ok=True)
    for n, t in files.items():
        (OUT / n).write_text(t)
    print(f"wrote {len(vectors)} vectors + keys.json + manifest.json to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
