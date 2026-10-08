"""Build and sign receipt bodies (SPEC §4–§5). Pure functions, so they're testable against the spec vectors."""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

import poaw_core

from .interfaces import Signer
from .models import Claim, ClaimIn, Decision, Reason, Verdict

MAX_SIGNED_BYTES = 4096  # the signer's message limit: AWS KMS Sign with MessageType=RAW refuses anything larger
# The facts limiter (limit_facts) bounds EVERY verifier's facts before the body is built, so no verifier, present or future, can
# push a receipt past MAX_SIGNED_BYTES. Intake counts exactly FACTS_ALLOWANCE_BYTES for facts (max_signed_size), and the limiter
# guarantees facts never exceed it.
FACT_STRING_MAX_BYTES = 512  # every string value, at any depth, is cut to this many UTF-8 bytes at a character boundary
FACT_LIST_MAX = 20           # every list, at any depth, keeps its first this-many items
FACTS_ALLOWANCE_BYTES = 1024  # canonical-JSON size of the whole facts object; over it, facts become {"facts_truncated": true}

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid(now_ms: int | None = None) -> str:
    t = int(time.time() * 1000) if now_ms is None else now_ms
    n = (t << 80) | int.from_bytes(os.urandom(10), "big")
    return "".join(_CROCKFORD[(n >> (5 * i)) & 31] for i in reversed(range(26)))


def ts(dt: datetime) -> str:
    """RFC 3339 UTC, millisecond precision, `Z` (SPEC §3)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.astimezone(timezone.utc).microsecond // 1000:03d}Z"


def _cut(v):
    if isinstance(v, str):
        return v.encode()[:FACT_STRING_MAX_BYTES].decode(errors="ignore")  # `ignore` drops a split trailing character
    if isinstance(v, list):
        return [_cut(x) for x in v[:FACT_LIST_MAX]]
    if isinstance(v, dict):
        return {k: _cut(x) for k, x in v.items()}
    return v


def limit_facts(facts: dict) -> dict:
    """Bound a verifier's facts (SPEC §4.4: ids, hashes, timestamps). Strings and lists are cut; if the result is still over
    FACTS_ALLOWANCE_BYTES (or cannot be measured), it is replaced by a fixed stub. Deterministic. It runs AFTER the verdict is
    decided and never touches it: the verdict is a function of the verifier's result, not of what the receipt records."""
    try:
        cut = _cut(facts)
        if len(poaw_core.jcs(cut)) <= FACTS_ALLOWANCE_BYTES:
            return cut
    except (TypeError, ValueError):
        pass
    return {"facts_truncated": True}


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


def max_signed_size(c: ClaimIn, issuer_name: str = "poaw-node") -> int:
    """Conservative upper bound, in bytes, of the message signed for this claim (domain prefix + canonical body).

    It builds the largest receipt the claim could yield: the longest verdict and reason strings, trust level 3 with its
    code hash and attestation, a huge attempt count, and facts at FACTS_ALLOWANCE_BYTES, the most limit_facts lets through."""
    claim = Claim(id="", workspace_id="", agent_ref=c.agent_id, client_claim_id=c.client_claim_id, action=c.action,
                  target=c.target, params=c.params, claimed_at=c.claimed_at, deadline_at=c.claimed_at)
    filler = "x" * (FACTS_ALLOWANCE_BYTES - len(poaw_core.jcs({"x": ""})))  # facts exactly at the limiter's ceiling
    decision = Decision(Verdict.UNVERIFIABLE, Reason.OBSERVED_AFTER_TOLERANCE, {"x": filler}, c.claimed_at)
    body = build_body(claim=claim, decision=decision, verifier_id=c.action, verifier_version="9" * 16, attempts=10**9,
                      issuer_key_id="k" * 64, issuer_name=issuer_name, issued_at=c.claimed_at, receipt_id="r" * 31,
                      trust_level=3, code_hash="sha384:" + "0" * 96, attestation_sha256="A" * 43)
    return len(poaw_core.SIG_DOMAIN + poaw_core.jcs(body))
