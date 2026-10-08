"""#235: a receipt must fit the signer's message limit (KMS RAW = 4096 bytes), and one bad claim must not stop the tick."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import poaw_core
import pytest
from fastapi.testclient import TestClient

from poaw_node import receipt as rc
from poaw_node.app import create_app
from poaw_node.interfaces import LocalSigner
from poaw_node.models import Claim, ClaimIn, Decision, Reason, Verdict
from poaw_node.service import Node

NOW = datetime(2026, 9, 25, 14, 0, tzinfo=timezone.utc)
LIMIT = 4096  # KMS RAW signing limit


def claim_in(**kw) -> ClaimIn:
    base = dict(client_claim_id="c" * 256, agent_id="a" * 256, action="github.commit.push", target="o/" + "r" * 510,
                params={"sha": "a" * 40, "branch": "main"}, claimed_at=NOW)
    base.update(kw)
    return ClaimIn(**base)


class Store:
    def __init__(self, leased=()):
        self.leased, self.submitted, self.rescheduled, self.recorded, self.flushed = list(leased), 0, [], [], 0

    async def submit(self, ws, c, *, claim_digest, deadline_at):
        self.submitted += 1
        return _claim("c1"), True

    async def lease_due(self, limit, lease, **kw):
        return self.leased

    async def reschedule(self, claim_id, next_at, error):
        self.rescheduled.append((claim_id, next_at, error))

    async def record(self, claim, receipt, **kw):
        self.recorded.append(claim.id)

    async def pending_alerts(self):
        self.flushed += 1
        return []


def _claim(cid, **kw) -> Claim:
    base = dict(id=cid, workspace_id="ws", agent_ref="a", client_claim_id="x", action="github.commit.push", target="o/r",
                params={"sha": "a" * 40, "branch": "main"}, claimed_at=NOW, deadline_at=NOW + timedelta(minutes=5), attempts=1)
    base.update(kw)
    return Claim(**base)


class FlakySigner(LocalSigner):
    """Raises (as a KMS limit/outage would) for one claim's receipts only."""
    def __init__(self, seed, bad_target):
        super().__init__(seed)
        self.bad_target = bad_target

    def sign(self, message: bytes) -> bytes:
        if self.bad_target.encode() in message:
            raise RuntimeError("KMS rejected the message")
        return super().sign(message)


def node(store, signer=None):
    return Node(store=store, signer=signer or LocalSigner(bytes(range(32))), connections=None, alerts=_Alerts(), http=None)


class _Alerts:
    async def send(self, *a, **k): ...


async def test_oversize_claim_refused_at_intake():
    """Params under their own cap, but the whole receipt would exceed the 4096-byte signer message."""
    n = node(Store())
    with pytest.raises(ValueError, match="too large"):
        await n.submit("ws", claim_in(params={"sha": "a" * 40, "branch": "b" * 1900}))
    assert n.store.submitted == 0


async def test_max_size_fields_with_small_params_still_accepted():
    n = node(Store())
    await n.submit("ws", claim_in())
    assert n.store.submitted == 1


def test_oversize_claim_is_a_422_over_http():
    class S(Store):
        async def workspace_for_key(self, k):
            return "ws"

        async def rate_take(self, *a, **k):
            return True

        async def bump_attempt(self, cid):
            return 1

        async def claim_status(self, ws, cid):
            return {"claim_id": cid, "state": "queued", "attempts": 1, "receipt_id": None, "verdict": None}

    async def get_node():
        return node(S())
    r = TestClient(create_app(get_node, log_id="l", tick_enabled=lambda: False)).post(
        "/v1/claims", headers={"Authorization": "Bearer k"},
        json={**claim_in(params={"sha": "a" * 40, "branch": "b" * 1900}).model_dump(mode="json")})
    assert r.status_code == 422


def test_worst_case_receipt_fits_the_limit_for_a_max_claim():
    """The intake bound must actually be conservative: a real max-size claim with level-3 fields and a fat verdict fits."""
    c = _claim("c1", agent_ref="a" * 256, client_claim_id="c" * 256, target="o/" + "r" * 510)
    d = Decision(Verdict.MISMATCH, Reason.CONTENT_MISMATCH, {"url": c.target, "x": "y" * 1000}, NOW)
    body = rc.build_body(claim=c, decision=d, verifier_id=c.action, verifier_version="1", attempts=1000,
                         issuer_key_id="k" * 43, issuer_name="poaw-node", issued_at=NOW, trust_level=3,
                         code_hash="sha384:" + "0" * 96, attestation_sha256="A" * 43)
    assert len(poaw_core.SIG_DOMAIN + poaw_core.jcs(body)) <= LIMIT


async def test_tick_survives_a_claim_whose_signing_fails_and_still_flushes_alerts():
    # An action with no verifier decides `unverifiable` without the network, which is enough to reach the signer.
    unsupported = dict(action="gmail.message.send", params={})
    store = Store([_claim("bad", target="BAD/target", **unsupported), _claim("good", **unsupported)])
    n = node(store, FlakySigner(bytes(range(32)), "BAD/target"))
    out = await n.tick()
    assert store.recorded == ["good"]                  # the next claim was still processed
    assert [r[0] for r in store.rescheduled] == ["bad"]  # the failing claim is backed off, not hot-looped
    assert store.flushed == 1                          # alerts still flushed
    assert out["errors"] == 1 and out["decided"] == 1


# -- round 2/3: the bound must hold for what the REAL verifiers put in facts ---------------------------------------------
import json
from types import SimpleNamespace

import httpx
import respx

from poaw_node.verifiers import REGISTRY, load_builtin
from poaw_node.verifiers import github as gh
from poaw_node.verifiers import http as httpv

load_builtin()
FAR = NOW + timedelta(days=30)  # "now" for check(): past every deadline, so non-final results settle into receipts


class StrictSigner(LocalSigner):
    """Enforces KMS RAW's limit: refuses any message over 4096 bytes."""
    def sign(self, message: bytes) -> bytes:
        if len(message) > LIMIT:
            raise RuntimeError(f"message of {len(message)} bytes exceeds the {LIMIT}-byte KMS RAW limit")
        return super().sign(message)


class Creds:
    def __init__(self, account):
        self.account = account

    def token(self):
        return "tok"

    def account_id(self):
        return self.account


class Conns:
    def __init__(self, account=None):
        self.account = account

    async def credentials(self, ws, provider, target=None):
        return Creds(self.account)


NASTY = ["\U0001F600" * 64, 'q"' * 40, "\\" * 64, "\x01\x02" * 40, "é" * 64, "plain-" * 20]
FAILING_RUNS = [{"name": f"{i:03d}" + NASTY[i % len(NASTY)] * 4, "status": "completed", "conclusion": "failure"} for i in range(400)]


def _runs_of(kind: str) -> list[dict]:  # 400 failing runs whose (sorted-first) names are ALL of one nasty kind
    return [{"name": f"{i:03d}" + kind * 4, "status": "completed", "conclusion": "failure"} for i in range(400)]
H64 = "e" * 64


def _grow(action, key, rest):
    """The largest claim of `action` that intake accepts, growing the free-text param `key`."""
    best = None
    for size in range(1, 2000, 7):
        c = claim_in(action=action, target="o/r", params={**rest, key: "b" * size})
        if rc.max_signed_size(c) > rc.MAX_SIGNED_BYTES:
            break
        best = c
    return best


def _mock_github_push():
    respx.get(url__regex=r".*/commits/.*").respond(200, json={"commit": {"committer": {"date": "2026-09-25T14:00:00Z"}}})
    respx.get(url__regex=r".*/compare/.*").respond(200, json={"status": "diverged"})


def _mock_github_pr():
    respx.get(url__regex=r".*/pulls/.*").respond(200, json={"state": "closed", "base": {"ref": "r" * 255},
                                                            "head": {"sha": "f" * 40}, "created_at": "2026-09-25T14:00:00Z"})


def _mock_github_checks(kind=None):
    runs = FAILING_RUNS if kind is None else _runs_of(kind)
    respx.get(url__regex=r".*/check-suites.*").respond(200, json={"total_count": 1, "check_suites": []})
    respx.get(url__regex=r".*/check-runs.*").respond(200, json={"total_count": len(runs), "check_runs": runs})


def _mock_http():
    respx.get(url__regex=r"https://93\.184\.216\.34.*").respond(200, text="a different body")


def _mock_slack():
    respx.get(url__regex=r".*conversations\.history.*").respond(200, json={"ok": True, "messages": [{"ts": "1790000000.000100", "text": "other"}]})


def _mock_x():
    respx.get(url__regex=r".*/tweets/.*").respond(200, json={"data": {"author_id": "9" * 19, "created_at": "2026-09-25T14:00:00.000Z",
                                                                      "text": "other"}})


# action -> (largest valid claim intake accepts, destination mock, connection account bound, expected verdict)
WORST_CASE = {
    "github.commit.push": (lambda: _grow("github.commit.push", "branch", {"sha": "a" * 40}), _mock_github_push, None),
    "github.pr.open": (lambda: _grow("github.pr.open", "base", {"number": 10**9, "head_sha": "a" * 40}), _mock_github_pr, None),
    "github.checks.pass": (lambda: claim_in(action="github.checks.pass", target="o/r", params={"sha": "a" * 40}), _mock_github_checks, None),
    "http.url.status": (lambda: claim_in(action="http.url.status", target="https://example.com/" + "p" * 491,
                                         params={"status": 200, "content_fingerprint": "sha256:" + "A" * 43}), _mock_http, None),
    "slack.message.post": (lambda: claim_in(action="slack.message.post", target="slack://T" + "A" * 20 + "/C" + "B" * 20,
                                            params={"ts": "1790000000.000100", "text_sha256": H64}), _mock_slack, "T" + "A" * 20),
    "x.post.publish": (lambda: claim_in(action="x.post.publish", target="@" + "h" * 15,
                                        params={"post_id": "9" * 20, "text_sha256": H64}), _mock_x, "1" * 19),
}


def test_every_registered_verifier_has_a_worst_case_driver():
    assert set(REGISTRY) <= set(WORST_CASE), f"no worst-case driver for {set(REGISTRY) - set(WORST_CASE)}"


CASES = [(a, None) for a in sorted(REGISTRY)] + [("github.checks.pass", k) for k in NASTY]


@pytest.mark.parametrize("action,kind", CASES, ids=[f"{a}-{i}" for i, (a, _) in enumerate(CASES)])
@respx.mock
async def test_every_verifiers_real_worst_case_receipt_fits_a_strict_signer(action, kind, monkeypatch):
    assert action in WORST_CASE, f"{action} has no worst-case driver: add one to WORST_CASE"
    make, mock, account = WORST_CASE[action]
    if kind is not None:
        mock = lambda: _mock_github_checks(kind)
    c = make()
    assert c is not None and rc.max_signed_size(c) <= rc.MAX_SIGNED_BYTES   # a valid claim that intake accepts
    REGISTRY[action].params.model_validate(c.params)

    async def public(host):
        return "93.184.216.34"
    monkeypatch.setattr(httpv, "resolve_public", public)
    mock()
    store = Store()
    n = Node(store=store, signer=StrictSigner(bytes(range(32))), connections=Conns(account), alerts=_Alerts(),
             http=httpx.AsyncClient())
    claim = _claim("c", agent_ref=c.agent_id, client_claim_id=c.client_claim_id, action=c.action, target=c.target,
                   params=c.params, deadline_at=NOW + timedelta(minutes=5))
    rid = await n.check(claim, attempts=10**9, now=FAR)   # the real verifier runs; signing raises past 4096 bytes
    assert rid is not None and store.recorded == ["c"]


@respx.mock
async def test_codex_repro_is_accepted_and_signs():
    """256-char ids, target o/r, 1500-char branch: the old bound said 4083 but the receipt was 4355. Facts are now capped
    centrally (the branch echo is cut to 512 bytes), so the claim is accepted AND its real mismatch receipt fits."""
    c = claim_in(target="o/r", params={"sha": "a" * 40, "branch": "b" * 1500})
    assert rc.max_signed_size(c) <= LIMIT
    _mock_github_push()
    store = Store()
    n = Node(store=store, signer=StrictSigner(bytes(range(32))), connections=Conns(None), alerts=_Alerts(), http=httpx.AsyncClient())
    claim = _claim("c", agent_ref=c.agent_id, client_claim_id=c.client_claim_id, target="o/r", params=c.params)
    assert await n.check(claim, attempts=10**9, now=FAR) is not None


async def test_failing_checks_list_is_capped_by_encoded_bytes():
    claim = _claim("c", action="github.checks.pass", target="o/r", params={"sha": "a" * 40})
    for names in (FAILING_RUNS, [{"name": "\U0001F600" * 64, "status": "completed", "conclusion": "failure"}] * 10):
        with respx.mock:
            respx.get(url__regex=r".*/check-suites.*").respond(200, json={"total_count": 1, "check_suites": []})
            respx.get(url__regex=r".*/check-runs.*").respond(200, json={"total_count": len(names), "check_runs": names})
            async with httpx.AsyncClient() as client:
                facts = (await gh.checks_pass(claim, None, client)).facts
        assert len(poaw_core.jcs(facts["failing"])) <= gh.MAX_FAILING_BYTES
        assert all(len(n.encode()) <= gh.MAX_FAILING_NAME for n in facts["failing"])
        assert facts["failing_total"] == len(names)


async def test_past_deadline_poison_claim_is_backed_off_into_the_future():
    unsupported = dict(action="gmail.message.send", params={}, deadline_at=NOW - timedelta(days=1))
    store = Store([_claim("bad", target="BAD/target", **unsupported)])
    n = node(store, FlakySigner(bytes(range(32)), "BAD/target"))
    await n.tick()
    (_, next_at, _), = store.rescheduled
    assert next_at > datetime.now(timezone.utc)


# -- the central facts limiter: sound for ANY verifier, including future ones ---------------------------------------------
from poaw_node.models import Observed
from poaw_node.verifiers import VerifierSpec


def _fake_spec(facts, outcome=Verdict.VERIFIED, reason=None):
    async def run(claim, creds, client):
        return Observed(facts, outcome, reason, observed_at=NOW)
    return VerifierSpec("test.fake.big", "1", None, timedelta(minutes=5), timedelta(minutes=10), run)


async def _check_with(monkeypatch, facts, **kw):
    monkeypatch.setitem(REGISTRY, "test.fake.big", _fake_spec(facts, **kw))
    store = Store()
    n = Node(store=store, signer=StrictSigner(bytes(range(32))), connections=None, alerts=_Alerts(), http=None)
    claim = _claim("c", agent_ref="a" * 256, client_claim_id="c" * 256, action="test.fake.big", target="t" * 512, params={})
    captured = []
    real = store.record

    async def record(c, receipt, **k):
        captured.append(receipt)
        await real(c, receipt, **k)
    store.record = record
    rid = await n.check(claim, attempts=10**9, now=NOW)
    return rid, captured


async def test_any_verifiers_huge_facts_still_sign_with_the_same_verdict(monkeypatch):
    facts = {"big": "x" * 10_000, "items": list(range(1000)), "names": ["n" * 500] * 1000, **{f"k{i}": i for i in range(500)}}
    for outcome, reason, want in ((Verdict.VERIFIED, None, "verified"), (Verdict.MISMATCH, Reason.CONTENT_MISMATCH, "mismatch"),
                                  (Verdict.FAILED, Reason.NOT_FOUND, "failed")):
        rid, (receipt,) = await _check_with(monkeypatch, facts, outcome=outcome, reason=reason)
        assert rid and receipt["body"]["verdict"]["value"] == want
        assert receipt["body"]["observation"]["facts"].get("facts_truncated") is True


async def test_modest_facts_are_untouched(monkeypatch):
    facts = {"sha": "a" * 40, "status": 200, "names": ["a", "b"]}
    _, (receipt,) = await _check_with(monkeypatch, facts)
    assert receipt["body"]["observation"]["facts"] == facts


async def test_long_strings_and_lists_are_cut_without_dropping_keys(monkeypatch):
    _, (r1,) = await _check_with(monkeypatch, {"s": "é" * 1000})
    got = r1["body"]["observation"]["facts"]["s"]
    assert len(got.encode()) <= rc.FACT_STRING_MAX_BYTES and got.startswith("é") and got.endswith("é")  # char boundary
    _, (r2,) = await _check_with(monkeypatch, {"l": list(range(100))})
    assert len(r2["body"]["observation"]["facts"]["l"]) == rc.FACT_LIST_MAX
    _, (r3,) = await _check_with(monkeypatch, {"nested": {"t": ["z" * 900]}})
    assert len(r3["body"]["observation"]["facts"]["nested"]["t"][0].encode()) == rc.FACT_STRING_MAX_BYTES


def test_limiter_is_deterministic():
    facts = {"b": "x" * 5000, "a": list(range(500)), **{f"k{i}": "v" * 100 for i in range(50)}}
    assert rc.limit_facts(facts) == rc.limit_facts(dict(reversed(list(facts.items()))))
    assert rc.limit_facts(facts) == rc.limit_facts(facts) == {"facts_truncated": True}


@respx.mock
async def test_oversized_destination_values_pr_base_and_x_author(monkeypatch):
    """The two verifiers that put raw destination strings in facts: a hostile destination cannot break signing."""
    async def public(host):
        return "93.184.216.34"
    monkeypatch.setattr(httpv, "resolve_public", public)
    respx.get(url__regex=r".*/pulls/.*").respond(200, json={"state": "s" * 5000, "base": {"ref": "r" * 5000},
                                                            "head": {"sha": "f" * 5000}, "created_at": "2026-09-25T14:00:00Z"})
    respx.get(url__regex=r".*/tweets/.*").respond(200, json={"data": {"author_id": "9" * 5000, "created_at": "c" * 5000}})
    for action, claim_kw, account in (
            ("github.pr.open", dict(target="o/r", params={"number": 7, "base": "main"}), None),
            ("x.post.publish", dict(target="@" + "h" * 15, params={"post_id": "9" * 20, "text_sha256": H64}), "1" * 19)):
        store = Store()
        n = Node(store=store, signer=StrictSigner(bytes(range(32))), connections=Conns(account), alerts=_Alerts(),
                 http=httpx.AsyncClient())
        claim = _claim("c", agent_ref="a" * 256, client_claim_id="c" * 256, action=action, **claim_kw)
        assert await n.check(claim, attempts=10**9, now=NOW) is not None and store.recorded == ["c"]
