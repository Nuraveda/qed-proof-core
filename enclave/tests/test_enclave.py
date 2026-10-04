import asyncio
import json
import socket
import struct
from datetime import datetime, timedelta, timezone

import httpx
import poaw_core
import pytest
from poaw_node import receipt
from poaw_node.models import Claim

from poaw_enclave import nsm as nsm_mod
from poaw_enclave import server
from poaw_enclave.nsm import FakeNsm

SHA = "a" * 40
API = "https://api.github.com"
NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)


def make_request(action="github.commit.push", params=None, token="tok", **over):
    claim = Claim(id="c1", workspace_id="w1", agent_ref="agent-1", client_claim_id="cc-1", action=action,
                  target="octo/repo", params=params or {"sha": SHA, "branch": "main"},
                  claimed_at=NOW - timedelta(minutes=1), deadline_at=NOW + timedelta(minutes=14))
    obj = {"id": claim.id, "workspace_id": "w1", "agent_ref": "agent-1", "action": action, "target": "octo/repo",
           "params": claim.params, "claimed_at": receipt.ts(claim.claimed_at), "deadline_at": receipt.ts(claim.deadline_at),
           "client_claim_id": "cc-1", "claim_digest": receipt.claim_object(claim)["claim_digest"]}
    req = {"job_id": "job-1", "claim": obj, "token": token, "attempts": 1}
    req.update(over)
    return req


def client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def ok_handler(request: httpx.Request):
    p = request.url.path
    if p.endswith(f"/commits/{SHA}"):
        return httpx.Response(200, json={"commit": {"committer": {"date": "2026-10-04T11:00:00Z"}}})
    if "/compare/" in p:
        return httpx.Response(200, json={"status": "ahead"})
    return httpx.Response(404)


async def run(req, handler=ok_handler, nsm=None, actions=frozenset({"github.commit.push"})):
    nsm = nsm or FakeNsm()
    raw = req if isinstance(req, bytes) else json.dumps(req).encode()
    async with client(handler) as http:
        return await server.process(raw, nsm=nsm, http=http, now=lambda: NOW, actions=actions), nsm


# -- framing ------------------------------------------------------------------------------------------------------
async def test_framing_roundtrip_over_server():
    nsm = FakeNsm()
    async with client(ok_handler) as http:
        def listener():
            s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(); s.setblocking(False); return s
        srv = await server.serve(nsm=nsm, http=http, listener=listener, now=lambda: NOW,
                                 actions=frozenset({"github.commit.push"}))
        port = srv.sockets[0].getsockname()[1]
        for _ in range(2):  # sequential connections
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(server.encode_frame(make_request()))
            (n,) = struct.unpack(">I", await r.readexactly(4))
            resp = json.loads(await r.readexactly(n))
            assert resp["outcome"] == "decided" and resp["job_id"] == "job-1"
            w.close()
        srv.close()


async def test_oversize_frame_rejected():
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack(">I", server.MAX_FRAME + 1))
    with pytest.raises(server.BadRequest):
        await server.read_frame(reader)


async def test_clean_eof_and_truncated():
    r = asyncio.StreamReader(); r.feed_eof()
    assert await server.read_frame(r) is None
    r = asyncio.StreamReader(); r.feed_data(struct.pack(">I", 10) + b"abc"); r.feed_eof()
    with pytest.raises(server.BadRequest):
        await server.read_frame(r)


# -- validation ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("mut", [
    lambda r: r.pop("token"),
    lambda r: r.update(extra=1),
    lambda r: r.update(attempts=True),
    lambda r: r.update(attempts=-1),
    lambda r: r.update(token=5),
    lambda r: r["claim"].update(claimed_at="2026-10-04T12:00:00"),
    lambda r: r["claim"].update(params=[]),
    lambda r: r["claim"].update(unknown="x"),
    lambda r: r["claim"].update(target="octo/other"),  # digest no longer matches
    lambda r: r["claim"].update(claim_digest="sha256:" + "0" * 64),
])
async def test_request_validation(mut):
    req = make_request(); mut(req)
    resp, nsm = await run(req)
    assert resp["outcome"] == "error" and resp["error"].startswith("bad_request")
    assert resp["attestation"] is None and nsm.calls == []


async def test_invalid_json():
    resp, _ = await run(b"{not json")
    assert resp["outcome"] == "error"


# -- decisions ----------------------------------------------------------------------------------------------------
async def test_commit_push_decided_with_c1_attestation():
    resp, nsm = await run(make_request())
    assert resp["outcome"] == "decided" and resp["verifier"] == {"id": "github.commit.push", "version": "1"}
    d = resp["decision"]
    assert d["verdict"] == "verified" and d["reason"] is None
    assert d["facts"]["branch_contains_sha"] is True and d["observed_at"].endswith("Z")
    doc = poaw_core.b64u_decode(resp["attestation"])
    assert doc == nsm_mod.cbor2.dumps({"fake": True, "user_data": nsm.calls[0]})
    req = make_request()
    expect = server.reference_statement_digest({
        "claim": {"claim_digest": req["claim"]["claim_digest"]},
        "observation": {"verifier": {"id": "github.commit.push", "version": "1"}, "observed_at": d["observed_at"],
                        "facts": d["facts"]},
        "verdict": {"value": "verified"}})
    assert nsm.calls == [expect] and len(expect) == 32
    if hasattr(poaw_core, "enclave_statement_digest"):
        body = {"claim": {"claim_digest": req["claim"]["claim_digest"]},
                "observation": {"verifier": {"id": "github.commit.push", "version": "1"},
                                "observed_at": d["observed_at"], "facts": d["facts"]},
                "verdict": {"value": "verified"}}
        assert poaw_core.enclave_statement_digest(body) == expect


async def test_token_is_passed_to_github():
    seen = []
    def h(request):
        seen.append(request.headers.get("authorization"))
        return ok_handler(request)
    await run(make_request(token="secret-tok"), handler=h)
    assert seen and all(a == "Bearer secret-tok" for a in seen)


async def test_failed_final_includes_reason_in_attestation():
    # commit absent, repo readable, past the deadline -> failed/not_found, decided
    def h(request):
        return httpx.Response(200, json={}) if request.url.path == "/repos/octo/repo" else httpx.Response(404)
    req = make_request()
    late = NOW + timedelta(hours=1)
    async with client(h) as http:
        nsm = FakeNsm()
        resp = await server.process(json.dumps(req).encode(), nsm=nsm, http=http, now=lambda: late,
                                    actions=frozenset({"github.commit.push"}))
    assert resp["outcome"] == "decided" and resp["decision"]["verdict"] == "failed"
    assert resp["decision"]["reason"] == "not_found"


async def test_retry_when_absent_so_far():
    def h(request):
        return httpx.Response(200, json={}) if request.url.path == "/repos/octo/repo" else httpx.Response(404)
    resp, nsm = await run(make_request(), handler=h)
    assert resp["outcome"] == "retry" and resp["decision"] is None and resp["attestation"] is None
    assert nsm.calls == []


async def test_transport_error_retries():
    def h(request):
        raise httpx.ConnectError("boom")
    resp, _ = await run(make_request(), handler=h)
    assert resp["outcome"] == "retry"


async def test_error_never_decided_when_verifier_raises(monkeypatch):
    from poaw_node.verifiers import REGISTRY
    async def boom(*a):
        raise RuntimeError("bug")
    from dataclasses import replace
    server.load_builtin()
    monkeypatch.setitem(REGISTRY, "github.commit.push", replace(REGISTRY["github.commit.push"], run=boom))
    resp, nsm = await run(make_request())
    assert resp["outcome"] == "error" and resp["attestation"] is None and resp["decision"] is None
    assert nsm.calls == []


async def test_nsm_failure_is_error_not_decided():
    resp, _ = await run(make_request(), nsm=FakeNsm(fail=True))
    assert resp["outcome"] == "error" and resp["attestation"] is None


async def test_disallowed_action_rejected():
    req = make_request(action="github.pr.open", params={"number": 1})
    resp, nsm = await run(req)
    assert resp["outcome"] == "error" and resp["error"] == "action_not_allowed" and nsm.calls == []


async def test_default_allowlist(monkeypatch):
    monkeypatch.delenv("QED_ENCLAVE_ACTIONS", raising=False)
    assert server.allowed_actions() == frozenset({"github.commit.push"})
    monkeypatch.setenv("QED_ENCLAVE_ACTIONS", "a.b.c, github.pr.open")
    assert server.allowed_actions() == frozenset({"a.b.c", "github.pr.open"})


# -- nsm ------------------------------------------------------------------------------------------------------------
def test_nsm_cbor_shapes():
    ud = bytes(range(32))
    assert nsm_mod.cbor2.loads(nsm_mod.encode_attestation_request(ud)) == {
        "Attestation": {"user_data": ud, "nonce": None, "public_key": None}}
    assert nsm_mod.decode_attestation_response(nsm_mod.cbor2.dumps({"Attestation": {"document": b"doc"}})) == b"doc"
    with pytest.raises(nsm_mod.NsmError):
        nsm_mod.decode_attestation_response(nsm_mod.cbor2.dumps({"Error": "InternalError"}))
    assert nsm_mod.NSM_IOCTL == 0xC0200A00


# -- forwarder ------------------------------------------------------------------------------------------------------
async def test_forwarder_relays_bytes():
    from poaw_enclave.forwarder import start_forwarder
    async def echo(r, w):
        w.write((await r.read(100)).upper()); await w.drain(); w.close()
    up = await asyncio.start_server(echo, "127.0.0.1", 0)
    up_port = up.sockets[0].getsockname()[1]
    def tcp():
        s = socket.socket(); s.setblocking(False); return s
    fwd = await start_forwarder("127.0.0.1", 0, upstream_connect=tcp, address=("127.0.0.1", up_port))
    r, w = await asyncio.open_connection("127.0.0.1", fwd.sockets[0].getsockname()[1])
    w.write(b"hello"); await w.drain()
    assert await asyncio.wait_for(r.read(100), 5) == b"HELLO"
    w.close(); fwd.close(); up.close()
