"""SPEC §7.1: the attestation vectors, and check.py end to end (CLI included) at trust level 3."""
import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).parents[1] / "tools"
VECTORS = Path(__file__).parents[1] / "vectors"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(Path(__file__).parents[2] / "core-python" / "src"))
import check as C  # noqa: E402
import poaw_core as p  # noqa: E402

MANIFEST = json.loads((VECTORS / "manifest.json").read_text())
ENTRIES = MANIFEST["attestation_vectors"]


def load(name):
    return json.loads((VECTORS / name).read_text())


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e["file"])
def test_attestation_vector(entry):
    r = C.check(load(entry["file"]), load(entry["keyset"]), nitro_root=C.load_root_der(str(VECTORS / entry["nitro_root"])))
    got = {"valid": r["valid"], "verdict": r["verdict"], "achieved_trust_level": r["achieved_trust_level"], "checks": r["checks"]}
    assert got == entry["expected"], entry["description"]


def test_vector_ids():
    assert [e["file"][:3] for e in ENTRIES] == ["042", "043", "044", "045", "046", "047", "048"]
    assert [e["expected"]["checks"]["attestation"] for e in ENTRIES] == [
        True, "attestation_chain", "attestation_invalid", "pcr_mismatch", "statement_mismatch", "unknown_build",
        "attestation_invalid"]
    assert [e["expected"]["achieved_trust_level"] for e in ENTRIES] == [1] * 7


def test_real_aws_root_rejects_the_test_chain():
    e = ENTRIES[0]
    r = C.check(load(e["file"]), load(e["keyset"]))  # no override: pinned AWS root
    assert r["valid"] and r["checks"]["attestation"] == "attestation_chain" and r["achieved_trust_level"] == 1


def test_builds_come_from_the_issuer_key_set():
    e = ENTRIES[0]
    keys = load(e["keyset"])
    root = C.load_root_der(str(VECTORS / e["nitro_root"]))
    assert C.check(load(e["file"]), {**keys, "verifier_builds": []}, nitro_root=root)["checks"]["attestation"] == "unknown_build"
    no_builds = {k: v for k, v in keys.items() if k != "verifier_builds"}
    assert C.check(load(e["file"]), no_builds, nitro_root=root)["checks"]["attestation"] == "unknown_build"


def test_resigned_receipt_with_new_verdict_fails_statement():
    # An issuer that re-signs the body with a different verdict cannot reuse the enclave's document.
    e = ENTRIES[0]
    receipt = load(e["file"])
    body = copy.deepcopy(receipt["body"])
    body["verdict"] = {"value": "mismatch", "reason_code": "content_mismatch"}
    key_a = __import__("cryptography.hazmat.primitives.asymmetric.ed25519", fromlist=["x"]).Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))  # gitleaks:allow (RFC 8032 public test key)
    forged = {"body": body, "signature": p.sign_body(key_a, body), "attestation_document": receipt["attestation_document"]}
    r = C.check(forged, load(e["keyset"]), nitro_root=C.load_root_der(str(VECTORS / e["nitro_root"])))
    assert r["valid"] and r["checks"]["attestation"] == "statement_mismatch" and r["achieved_trust_level"] == 1


def test_the_document_travels_outside_the_signed_body():
    e = ENTRIES[0]
    receipt, keys = load(e["file"]), load(e["keyset"])
    root = C.load_root_der(str(VECTORS / e["nitro_root"]))
    assert "document" not in receipt["body"]["attestation"] and len(receipt["body"]["attestation"]["document_sha256"]) == 43
    absent = {k: v for k, v in receipt.items() if k != "attestation_document"}
    r = C.check(absent, keys, nitro_root=root)
    assert r["valid"] and r["checks"]["attestation"] == "attestation_invalid" and r["achieved_trust_level"] == 1
    assert len(json.dumps(receipt["body"])) < 4096  # the signed message stays far below KMS's 4096-byte limit


def test_levels_one_and_two_do_not_get_an_attestation_check():
    r = C.check(load("001-valid-verified.json"), load("keys.json"))
    assert "attestation" not in r["checks"] and r["achieved_trust_level"] == 1
    # L3 without an attestation fails the schema first (vector 013) and stays invalid
    r = C.check(load("013-level3-without-attestation.json"), load("keys.json"))
    assert not r["valid"] and "attestation" not in r["checks"]


def test_cli_nitro_root_flag():
    e = ENTRIES[0]
    out = subprocess.run([sys.executable, str(TOOLS / "check.py"), str(VECTORS / e["file"]), str(VECTORS / e["keyset"]),
                          "--nitro-root", str(VECTORS / e["nitro_root"])], capture_output=True, text=True, check=True).stdout
    r = json.loads(out)
    assert r["checks"]["attestation"] is True and r["achieved_trust_level"] == 1  # offline: no anchor, so not 3
    out = subprocess.run([sys.executable, str(TOOLS / "check.py"), str(VECTORS / e["file"]), str(VECTORS / e["keyset"])],
                         capture_output=True, text=True, check=True).stdout
    assert json.loads(out)["checks"]["attestation"] == "attestation_chain"


def test_level_3_needs_a_verified_anchor(monkeypatch):
    """Levels are cumulative (§7.1): a passing attestation reaches 3 only once the anchor verifies too."""
    import types

    e = ENTRIES[0]
    receipt, keyset = load(e["file"]), load(e["keyset"])
    root = _der(VECTORS / e["nitro_root"])
    # A one-leaf log holding just this receipt (its root is the leaf hash), plus an anchor the fake chain accepts.
    receipt["proof"] = {"log_id": "test", "leaf_index": 0, "tree_size": 1, "root_hash": p.b64u(p.leaf_hash(receipt)),
                        "inclusion": [], "anchor": {"chain": "eip155:84532", "scheme": "eas", "uid": "0x" + "00" * 32,
                                                    "tx_hash": "0x" + "00" * 32, "tree_size": 1}}
    fake = types.ModuleType("anchor_check")
    fake.check_anchor = lambda proof, keyset, rpc, dec, cons: {"ok": True, "reason": None, "proven_by": "2026-10-04T00:00:00Z"}
    fake.check_consistency = lambda *a, **k: True
    monkeypatch.setitem(sys.modules, "anchor_check", fake)
    r = C.check(receipt, keyset, "https://rpc.invalid", nitro_root=root)
    assert r["checks"]["attestation"] is True and r["checks"]["anchor"] is True and r["achieved_trust_level"] == 3
    fake.check_anchor = lambda *a: {"ok": False, "reason": "attestation_not_found", "proven_by": None}
    r = C.check(receipt, keyset, "https://rpc.invalid", nitro_root=root)
    assert r["checks"]["attestation"] is True and r["achieved_trust_level"] == 1


def _der(path):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    return x509.load_pem_x509_certificate(path.read_bytes()).public_bytes(Encoding.DER)
