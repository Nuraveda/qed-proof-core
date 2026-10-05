"""Enclave request server (protocol C4, docs/lanes/enclave-verifier.md).

Frames: 4-byte big-endian length + UTF-8 JSON; one request -> one response; connections handled sequentially.
The decision is made by the same open code as the node (`poaw_node.verifiers.REGISTRY` + `verdict.decide`); the
attestation binds claim_digest, verifier id/version, observed_at, facts and verdict (C1) to this build's PCR0.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import ssl
import struct
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import certifi
import httpx
import poaw_core
from poaw_node import receipt
from poaw_node.models import Claim
from poaw_node.verdict import decide
from poaw_node.verifiers import REGISTRY, load_builtin

from . import VSOCK_PORT
from .nsm import Nsm

MAX_FRAME = 1 << 20
DEFAULT_ACTIONS = "github.commit.push,github.pr.open,github.checks.pass"
_CLAIM_STR = ("id", "workspace_id", "agent_ref", "action", "target", "client_claim_id", "claim_digest")


class BadRequest(ValueError):
    pass


def allowed_actions() -> frozenset[str]:
    raw = os.environ.get("QED_ENCLAVE_ACTIONS", DEFAULT_ACTIONS)
    return frozenset(a.strip() for a in raw.split(",") if a.strip())


# -- framing ------------------------------------------------------------------------------------------------------
def encode_frame(obj: Any) -> bytes:
    data = json.dumps(obj, separators=(",", ":")).encode()
    if len(data) > MAX_FRAME:
        raise ValueError("frame too large")
    return struct.pack(">I", len(data)) + data


async def read_frame(reader: asyncio.StreamReader) -> bytes | None:
    """Return the payload, or None on a clean EOF before a frame. Oversize frames raise BadRequest."""
    try:
        head = await reader.readexactly(4)
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            return None
        raise BadRequest("truncated frame header")
    (n,) = struct.unpack(">I", head)
    if n > MAX_FRAME:
        raise BadRequest("frame too large")
    try:
        return await reader.readexactly(n)
    except asyncio.IncompleteReadError:
        raise BadRequest("truncated frame")


# -- request validation -------------------------------------------------------------------------------------------
def _time(v: Any, name: str) -> datetime:
    if not isinstance(v, str):
        raise BadRequest(f"{name} must be an RFC 3339 string")
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        raise BadRequest(f"{name} is not RFC 3339")
    if d.tzinfo is None:
        raise BadRequest(f"{name} needs a timezone")
    return d


def parse_request(obj: Any) -> tuple[str, Claim, str | None, int]:
    """Strictly validate a C4 request. Unknown keys are rejected. Returns (job_id, claim, token, attempts)."""
    if not isinstance(obj, dict):
        raise BadRequest("request must be an object")
    if set(obj) != {"job_id", "claim", "token", "attempts"}:
        raise BadRequest("request keys must be exactly job_id, claim, token, attempts")
    job_id, c, token, attempts = obj["job_id"], obj["claim"], obj["token"], obj["attempts"]
    if not isinstance(job_id, str) or not job_id or len(job_id) > 256:
        raise BadRequest("job_id must be a non-empty string")
    if token is not None and not isinstance(token, str):
        raise BadRequest("token must be a string or null")
    if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 0:
        raise BadRequest("attempts must be a non-negative integer")
    if not isinstance(c, dict):
        raise BadRequest("claim must be an object")
    if set(c) != set(_CLAIM_STR) | {"params", "claimed_at", "deadline_at"}:
        raise BadRequest("claim has missing or unknown keys")
    for k in _CLAIM_STR:
        if not isinstance(c[k], str) or not c[k] or len(c[k]) > 512:
            raise BadRequest(f"claim.{k} must be a non-empty string")
    if not isinstance(c["params"], dict):
        raise BadRequest("claim.params must be an object")
    claim = Claim(id=c["id"], workspace_id=c["workspace_id"], agent_ref=c["agent_ref"],
                  client_claim_id=c["client_claim_id"], action=c["action"], target=c["target"], params=c["params"],
                  claimed_at=_time(c["claimed_at"], "claimed_at"), deadline_at=_time(c["deadline_at"], "deadline_at"),
                  attempts=attempts)
    if poaw_core.has_float(c["params"]):
        raise BadRequest("claim.params contains a float")
    if receipt.claim_object(claim)["claim_digest"] != c["claim_digest"]:
        raise BadRequest("claim_digest does not match the claim")  # the enclave never attests an unbound claim
    return job_id, claim, token, attempts


# -- the job --------------------------------------------------------------------------------------------------------
class _Creds:
    def __init__(self, token: str | None):
        self._t = token

    def token(self) -> str | None:
        return self._t


def statement_digest(*, claim_digest: str, verifier_id: str, verifier_version: str, observed_at: str, facts: dict,
                     verdict: dict) -> bytes:
    """C1 digest, computed by poaw_core (the same function checkers use)."""
    body = {"claim": {"claim_digest": claim_digest},
            "observation": {"verifier": {"id": verifier_id, "version": verifier_version}, "observed_at": observed_at,
                            "facts": facts},
            "verdict": verdict}
    fn = getattr(poaw_core, "enclave_statement_digest", None)
    return fn(body) if fn else reference_statement_digest(body)


def reference_statement_digest(body: dict) -> bytes:
    """C1 reference implementation, used only until `poaw_core.enclave_statement_digest` is available.
    SHA-256(JCS({claim_digest, verifier{id,version}, observed_at, facts, verdict}))."""
    o = body["observation"]
    statement = {"claim_digest": body["claim"]["claim_digest"],
                 "verifier": {"id": o["verifier"]["id"], "version": o["verifier"]["version"]},
                 "observed_at": o["observed_at"], "facts": o["facts"], "verdict": body["verdict"]}
    return poaw_core.sha256(poaw_core.jcs(statement))


def _resp(job_id: str, outcome: str, verifier: dict, decision=None, attestation=None, error: str | None = None) -> dict:
    r = {"job_id": job_id, "outcome": outcome, "verifier": verifier, "decision": decision, "attestation": attestation}
    if error is not None:
        r["error"] = error
    return r


def make_http_client() -> httpx.AsyncClient:
    # Normal TLS verification, inside the enclave, against the image's CA bundle.
    return httpx.AsyncClient(verify=ssl.create_default_context(cafile=certifi.where()))


async def process(raw: bytes, *, nsm: Nsm, http: httpx.AsyncClient, now: Callable[[], datetime] | None = None,
                  actions: frozenset[str] | None = None) -> dict:
    """One request -> one response. Never raises; never answers `decided` unless the attestation was produced."""
    now = now or (lambda: datetime.now(timezone.utc))
    actions = allowed_actions() if actions is None else actions
    unknown = {"id": "unknown", "version": "0"}
    job_id = ""
    try:
        try:
            obj = json.loads(raw.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise BadRequest("invalid JSON")
        if isinstance(obj, dict) and isinstance(obj.get("job_id"), str):
            job_id = obj["job_id"]
        job_id, claim, token, _attempts = parse_request(obj)
        unknown = {"id": claim.action, "version": "0"}
        load_builtin()
        spec = REGISTRY.get(claim.action)
        if claim.action not in actions or spec is None:
            return _resp(job_id, "error", unknown, error="action_not_allowed")
        verifier = {"id": spec.action, "version": spec.version}
        try:
            spec.params.model_validate(claim.params)
        except Exception:
            return _resp(job_id, "error", verifier, error="invalid_params")
        try:
            result = await spec.run(claim, _Creds(token), http)
        except Exception as exc:  # a verifier bug must never pass a claim (and the host must not see "decided")
            return _resp(job_id, "error", verifier, error=f"verifier_exception:{type(exc).__name__}")
        t = now()
        decision = decide(result, claimed_at=claim.claimed_at, deadline_at=claim.deadline_at, now=t,
                          tolerance=spec.tolerance)
        if decision is None:
            return _resp(job_id, "retry", verifier)
        if poaw_core.has_float(decision.facts):
            return _resp(job_id, "error", verifier, error="facts_contain_float")
        observed_at = receipt.ts(decision.observed_at or t)
        verdict = {"value": decision.verdict.value}
        if decision.reason is not None:
            verdict["reason_code"] = decision.reason.value
        digest = statement_digest(claim_digest=claim_digest_of(claim), verifier_id=verifier["id"],
                                  verifier_version=verifier["version"], observed_at=observed_at,
                                  facts=decision.facts, verdict=verdict)
        doc = nsm.attest(digest)
        return _resp(job_id, "decided", verifier,
                     {"verdict": decision.verdict.value, "reason": decision.reason.value if decision.reason else None,
                      "facts": decision.facts, "observed_at": observed_at}, poaw_core.b64u(doc))
    except BadRequest as exc:
        return _resp(job_id, "error", unknown, error=f"bad_request:{exc}")
    except Exception as exc:
        return _resp(job_id, "error", unknown, error=f"internal:{type(exc).__name__}")


def claim_digest_of(claim: Claim) -> str:
    return receipt.claim_object(claim)["claim_digest"]


# -- connection handling / serving --------------------------------------------------------------------------------
async def handle_connection(reader, writer, *, nsm: Nsm, http: httpx.AsyncClient, now=None, actions=None) -> None:
    try:
        try:
            raw = await read_frame(reader)
        except BadRequest as exc:
            writer.write(encode_frame(_resp("", "error", {"id": "unknown", "version": "0"}, error=f"bad_request:{exc}")))
            await writer.drain()
            return
        if raw is None:
            return
        writer.write(encode_frame(await process(raw, nsm=nsm, http=http, now=now, actions=actions)))
        await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


def vsock_listener(port: int = VSOCK_PORT) -> socket.socket:
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.bind((socket.VMADDR_CID_ANY, port))
    s.listen(8)
    s.setblocking(False)
    return s


async def serve(*, nsm: Nsm, http: httpx.AsyncClient, listener: Callable[[], socket.socket] = vsock_listener,
                now=None, actions=None) -> asyncio.AbstractServer:
    """Start the request server. `listener` is injectable so tests can use a loopback TCP socket instead of vsock."""
    lock = asyncio.Lock()

    async def _handler(reader, writer):
        async with lock:  # one request at a time
            await handle_connection(reader, writer, nsm=nsm, http=http, now=now, actions=actions)

    return await asyncio.start_server(_handler, sock=listener())
