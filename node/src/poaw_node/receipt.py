"""Build and sign receipt bodies (SPEC §4–§5). Pure functions, so they're testable against the spec vectors."""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

import poaw_core

from .interfaces import Signer
from .models import Claim, Decision

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid(now_ms: int | None = None) -> str:
    t = int(time.time() * 1000) if now_ms is None else now_ms
    n = (t << 80) | int.from_bytes(os.urandom(10), "big")
    return "".join(_CROCKFORD[(n >> (5 * i)) & 31] for i in reversed(range(26)))


def ts(dt: datetime) -> str:
    """RFC 3339 UTC, millisecond precision, `Z` (SPEC §3)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.astimezone(timezone.utc).microsecond // 1000:03d}Z"


def claim_object(c: Claim) -> dict:
    obj = {"action": c.action, "target": c.target, "params": c.params, "claimed_at": ts(c.claimed_at),
           "client_claim_id": c.client_claim_id}
    obj["claim_digest"] = poaw_core.claim_digest(obj)
    return obj


def build_body(*, claim: Claim, decision: Decision, verifier_id: str, verifier_version: str, attempts: int,
               issuer_key_id: str, issuer_name: str, issued_at: datetime, receipt_id: str | None = None, trust_level: int = 1,
               code_hash: str | None = None, attestation_sha256: str | None = None) -> dict:
    verdict = {"value": decision.verdict.value}
    if decision.reason is not None:
        verdict["reason_code"] = decision.reason.value
    observed_at = decision.observed_at or issued_at
    body = {
        "spec_version": poaw_core.SPEC_VERSION,
        "receipt_id": receipt_id or f"rcpt_{ulid()}",
        "issued_at": ts(issued_at),
        "issuer": {"key_id": issuer_key_id, "name": issuer_name},
        "agent": {"id": claim.agent_ref},
        "claim": claim_object(claim),
        "observation": {
            "verifier": {"id": verifier_id, "version": verifier_version},
            "observed_at": ts(observed_at),
            "deadline_at": ts(claim.deadline_at),
            "attempts": max(1, attempts),
            "facts": decision.facts,
        },
        "verdict": verdict,
        "trust_level": trust_level,
    }
    if code_hash is not None:
        body["observation"]["verifier"]["code_hash"] = code_hash
    if attestation_sha256 is not None:  # SPEC §4.1/§7.1: the body commits to the document by hash; the document travels outside it
        body["attestation"] = {"type": "aws-nitro-enclave", "document_sha256": attestation_sha256}
    if poaw_core.has_float(body):
        raise ValueError("receipt body contains a float; SPEC §3 allows integers only")
    return body


def sign(body: dict, signer: Signer) -> dict:
    kid = poaw_core.key_id(signer.public_key())
    if body["issuer"]["key_id"] != kid:
        raise ValueError("issuer.key_id does not match the signer's public key")
    sig = signer.sign(poaw_core.SIG_DOMAIN + poaw_core.jcs(body))
    return {"body": body, "signature": {"alg": "Ed25519", "key_id": kid, "value": poaw_core.b64u(sig)}}
