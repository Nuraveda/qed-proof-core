"""Orchestration: check a claim → decide → sign → record → alert. Used by both the API (first check inline) and the tick."""
from __future__ import annotations

import hashlib
import hmac
import inspect
import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone

import httpx
import poaw_core

from . import receipt as rc
from .interfaces import AlertSink, ConnectionStore, Signer
from .models import Claim, ClaimIn, Decision, Reason, Unverifiable, Verdict
from .store import Store
from .verdict import decide
from .verifiers import REGISTRY, load_builtin

ALERT_ON = {Verdict.FAILED, Verdict.LATE, Verdict.MISMATCH}
UNSUPPORTED_DEADLINE = timedelta(seconds=0)


@dataclass
class Node:
    store: Store
    signer: Signer
    connections: ConnectionStore
    alerts: AlertSink
    http: httpx.AsyncClient
    issuer_name: str = "poaw-node"
    alert_sink_name: str = "default"
    # Optional enclave path (trust level 3). Empty `enclave_actions` = off: nothing below changes behaviour.
    enclave_actions: frozenset[str] = frozenset()
    enclave_window: timedelta = timedelta(seconds=600)

    def __post_init__(self) -> None:
        load_builtin()
        self.key_id = poaw_core.key_id(self.signer.public_key())

    # -- intake ---------------------------------------------------------------------------------------------------
    @staticmethod
    def validate_params(c: ClaimIn) -> None:
        """Raise ValueError if params don't match the action's declared model (SECURITY F3)."""
        spec = REGISTRY.get(c.action)
        if spec is None:
            if c.params:
                raise ValueError("params must be empty for an action with no verifier")
            return
        spec.params.model_validate(c.params)

    async def submit(self, workspace_id: str, c: ClaimIn) -> tuple[Claim, bool]:
        self.validate_params(c)
        if (size := rc.max_signed_size(c, self.issuer_name)) > rc.MAX_SIGNED_BYTES:  # #235: KMS RAW refuses larger messages
            raise ValueError(f"claim too large: its receipt could reach {size} signed bytes, the limit is {rc.MAX_SIGNED_BYTES}")
        spec = REGISTRY.get(c.action)
        deadline = c.claimed_at + (spec.deadline if spec else UNSUPPORTED_DEADLINE)
        digest_obj = {"action": c.action, "target": c.target, "params": c.params, "claimed_at": rc.ts(c.claimed_at),
                      "client_claim_id": c.client_claim_id}
        return await self.store.submit(workspace_id, c, claim_digest=poaw_core.claim_digest(digest_obj),
                                       deadline_at=deadline)

    # -- enclave eligibility ---------------------------------------------------------------------------------------
    def enclave_eligible(self, claim: Claim, now: datetime | None = None) -> bool:
        """True while an enclave may still decide this claim: its action is enclave-enabled and it is inside the window.
        Eligible claims are skipped by the inline check and by the tick; after the window they are decided normally."""
        if not self.enclave_actions or claim.action not in self.enclave_actions or claim.created_at is None:
            return False
        return (now or datetime.now(timezone.utc)) < claim.created_at + self.enclave_window

    # -- checking -------------------------------------------------------------------------------------------------
    async def check(self, claim: Claim, *, attempts: int, now: datetime | None = None) -> str | None:
        """Run one check. Returns the receipt_id once decided, or None if the claim was rescheduled."""
        now = now or datetime.now(timezone.utc)
        spec = REGISTRY.get(claim.action)
        if spec is None:
            result = Unverifiable(Reason.UNSUPPORTED_ACTION, claim.action)
            verifier_id, version, tolerance = claim.action, "0", timedelta(0)
        else:
            verifier_id, version, tolerance = spec.action, spec.version, spec.tolerance
            try:
                creds = await _credentials(self.connections, claim, spec.provider) if spec.provider else None
                result = await spec.run(claim, creds, self.http)
            except Exception as exc:  # a verifier bug must never pass a claim
                result = exc

        decision = decide(result, claimed_at=claim.claimed_at, deadline_at=claim.deadline_at, now=now,
                          tolerance=tolerance)
        if decision is None:
            backoff = min(timedelta(seconds=30 * (2 ** min(attempts, 5))), timedelta(minutes=10))
            await self.store.reschedule(claim.id, min(now + backoff, claim.deadline_at), _describe(result))
            return None

        decision = replace(decision, facts=rc.limit_facts(decision.facts))  # after the verdict: size only, never the outcome
        body = rc.build_body(claim=claim, decision=decision, verifier_id=verifier_id, verifier_version=version,
                             attempts=attempts, issuer_key_id=self.key_id, issuer_name=self.issuer_name, issued_at=now)
        signed = rc.sign(body, self.signer)
        await self.store.record(claim, signed, alert=decision.verdict in ALERT_ON, sink=self.alert_sink_name)
        return body["receipt_id"]

    async def record_attested(self, claim: Claim, response: dict, *, accepted_codes, verify,
                              now: datetime | None = None) -> tuple[str | None, str | None]:
        """Record an enclave's decision as a trust-level-3 receipt. Returns (receipt_id, None), or (None, reason) with
        NOTHING recorded when the response doesn't check out.

        `verify(document_b64u)` returns an object with `.pcrs` ({int: bytes}) and `.user_data` (bytes) and raises when the
        attestation document is invalid (chain, signature). Here we then require: PCR0 == the receipt's code_hash, that
        code_hash is an accepted build, and user_data == the statement digest of the body we are about to sign."""
        now = now or datetime.now(timezone.utc)
        try:
            if response.get("outcome") != "decided":
                return None, "not_decided"
            dec, ver, doc = response.get("decision"), response.get("verifier") or {}, response.get("attestation")
            if not isinstance(dec, dict) or not isinstance(doc, str) or not doc:
                return None, "malformed_response"
            if ver.get("id") != claim.action or not isinstance(ver.get("version"), str):
                return None, "verifier_mismatch"
            observed = datetime.fromisoformat(str(dec["observed_at"]).replace("Z", "+00:00"))
            # observed_at is inside the attested statement, so it must survive formatting byte for byte (SPEC §3 form).
            if observed.tzinfo is None or rc.ts(observed) != dec["observed_at"]:
                return None, "malformed_response"
            reason = Reason(dec["reason"]) if dec.get("reason") else None
            decision = Decision(Verdict(dec["verdict"]), reason, dec.get("facts") or {}, observed)
            if decision.verdict is Verdict.UNVERIFIABLE or not isinstance(decision.facts, dict):
                return None, "not_decided"
        except (ValueError, KeyError, TypeError):
            return None, "malformed_response"
        try:
            att = verify(doc)
            pcr0 = att.pcrs[0].hex()
            user_data = bytes(att.user_data)
        except Exception as exc:
            return None, f"attestation_invalid:{type(exc).__name__}"
        code_hash = f"sha384:{pcr0}"
        if code_hash not in set(accepted_codes):
            return None, "unknown_build"
        try:
            body = rc.build_body(claim=claim, decision=decision, verifier_id=ver["id"], verifier_version=ver["version"],
                                 attempts=claim.attempts, issuer_key_id=self.key_id, issuer_name=self.issuer_name,
                                 issued_at=now, trust_level=3, code_hash=code_hash,
                                 attestation_sha256=poaw_core.b64u(hashlib.sha256(poaw_core.b64u_decode(doc)).digest()))
        except ValueError:  # includes a document that is not base64url
            return None, "malformed_response"
        if not hmac.compare_digest(user_data, _statement_digest(body)):
            return None, "statement_mismatch"
        try:  # never let a signing or storage failure escape as a 500: the claim stays queued for the normal path
            signed = rc.sign(body, self.signer)
            await self.store.record(claim, signed, alert=decision.verdict in ALERT_ON, sink=self.alert_sink_name,
                                    attestation_document=doc)
        except Exception as exc:
            return None, f"record_failed:{type(exc).__name__}"
        return body["receipt_id"], None

    async def tick(self, *, limit: int = 25, budget_s: float = 45.0) -> dict:
        """One scheduled pass: lease due claims, check each, then flush alerts. Stops taking work at the budget."""
        import time
        start, done, rescheduled, errors = time.monotonic(), 0, 0, 0
        skip = {"skip_enclave": (sorted(self.enclave_actions), self.enclave_window)} if self.enclave_actions else {}
        for claim in await self.store.lease_due(limit, timedelta(minutes=2), **skip):
            if time.monotonic() - start > budget_s:
                break
            try:
                rid = await self.check(claim, attempts=claim.attempts)
            except Exception as exc:  # #235: one claim that cannot be signed or stored must not stop the rest, or the alerts
                errors += 1
                print(json.dumps({"event": "tick.claim_error", "claim_id": claim.id, "error": type(exc).__name__,
                                  "detail": str(exc)[:300]}), flush=True)
                try:  # the store's own backoff, so the claim is not re-leased every two minutes; no receipt is written
                    backoff = min(timedelta(seconds=30 * (2 ** min(claim.attempts, 5))), timedelta(minutes=10))
                    await self.store.reschedule(claim.id, datetime.now(timezone.utc) + backoff,  # not capped at the deadline: a
                                                # past deadline would put it in the past and re-take it every tick
                                                f"tick_error:{type(exc).__name__}")
                except Exception:
                    pass
                continue
            done, rescheduled = done + (rid is not None), rescheduled + (rid is None)
        sent = await self.flush_alerts()
        return {"decided": done, "rescheduled": rescheduled, "errors": errors, "alerts_sent": sent}

    async def flush_alerts(self) -> int:
        sent = 0
        for a in await self.store.pending_alerts():
            try:
                await self.alerts.send(a["receipt"], alert_id=a["alert_id"], workspace_id=a.get("workspace_id"))
                await self.store.mark_alert(a["alert_id"], True)
                sent += 1
            except Exception as exc:
                await self.store.mark_alert(a["alert_id"], False, type(exc).__name__)
        return sent


def _statement_digest(body: dict) -> bytes:
    """SHA-256(JCS(statement)) per SPEC §7.1. Uses poaw_core's implementation when present."""
    fn = getattr(poaw_core, "enclave_statement_digest", None)
    if fn is not None:
        return fn(body)
    o = body["observation"]
    statement = {"claim_digest": body["claim"]["claim_digest"],
                 "verifier": {"id": o["verifier"]["id"], "version": o["verifier"]["version"]},
                 "observed_at": o["observed_at"], "facts": o["facts"], "verdict": body["verdict"]}
    return poaw_core.sha256(poaw_core.jcs(statement))


def _accepts_target(store) -> bool:
    """Whether `store.credentials` takes a `target` argument. Stores written before it existed take two."""
    try:
        params = inspect.signature(store.credentials).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.name == "target" or p.kind is inspect.Parameter.VAR_KEYWORD for p in params)


async def _credentials(store, claim: Claim, provider: str):
    if _accepts_target(store):
        return await store.credentials(claim.workspace_id, provider, target=claim.target)
    return await store.credentials(claim.workspace_id, provider)


def _describe(result) -> str:
    if isinstance(result, BaseException):
        return f"exception:{type(result).__name__}"
    reason = getattr(result, "reason", None)
    return f"{type(result).__name__}:{getattr(reason, 'value', reason)}"
