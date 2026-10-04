"""Enclave eligibility (C5): eligible claims are skipped by the inline check and the tick; after the window, normal."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from poaw_node import receipt as rc
from poaw_node.app import create_app
from poaw_node.interfaces import LocalSigner
from poaw_node.models import Claim
from poaw_node.service import Node

NOW = datetime.now(timezone.utc)


def claim(created, action="github.commit.push", cid="c1"):
    return Claim(id=cid, workspace_id="ws", agent_ref="a", client_claim_id="x", action=action, target="o/r",
                 params={}, claimed_at=NOW, deadline_at=NOW + timedelta(minutes=5), created_at=created)


class Store:
    def __init__(self, c):
        self.c, self.lease_kwargs, self.bumped = c, None, 0

    async def lease_due(self, limit, lease, **kw):
        self.lease_kwargs = kw
        return []

    async def flush(self): ...

    async def pending_alerts(self):
        return []

    async def workspace_for_key(self, k):
        return "ws"

    async def rate_take(self, *a, **k):
        return True

    async def submit(self, ws, c, *, claim_digest, deadline_at):
        return self.c, True

    async def bump_attempt(self, cid):
        self.bumped += 1
        return 1

    async def claim_status(self, ws, cid):
        return {"claim_id": cid, "state": "queued", "attempts": 0, "receipt_id": None, "verdict": None}


def node(store, actions=("github.commit.push",), window=600):
    n = Node(store=store, signer=LocalSigner(bytes(range(32))), connections=None, alerts=None, http=None,
             enclave_actions=frozenset(actions), enclave_window=timedelta(seconds=window))
    checked = []

    async def fake_check(c, *, attempts, now=None):
        checked.append(c.id)
        return "r1"
    n.check = fake_check
    return n, checked


def test_eligible_inside_window_only_for_listed_actions():
    n, _ = node(Store(None))
    assert n.enclave_eligible(claim(NOW - timedelta(seconds=10)))
    assert not n.enclave_eligible(claim(NOW - timedelta(seconds=601)))
    assert not n.enclave_eligible(claim(NOW, action="github.pr.open"))
    assert not n.enclave_eligible(claim(None))
    off, _ = node(Store(None), actions=())
    assert not off.enclave_eligible(claim(NOW))


async def test_tick_passes_the_skip_filter_only_when_enabled():
    s = Store(None)
    n, _ = node(s)
    await n.tick()
    assert s.lease_kwargs == {"skip_enclave": (["github.commit.push"], timedelta(seconds=600))}
    s2 = Store(None)
    off, _ = node(s2, actions=())
    await off.tick()
    assert s2.lease_kwargs == {}


@pytest.mark.parametrize("age,inline", [(5, False), (700, True)])
def test_inline_check_skips_eligible_claims_but_decides_after_the_window(age, inline):
    s = Store(claim(NOW - timedelta(seconds=age)))
    n, checked = node(s)
    app = create_app(lambda: _aw(n), log_id="l", tick_enabled=lambda: False)
    r = TestClient(app).post("/v1/claims", headers={"Authorization": "Bearer k"},
                             json={"client_claim_id": "x", "agent_id": "a", "action": "github.commit.push", "target": "o/r",
                                   "params": {"sha": "a" * 40, "branch": "main"}, "claimed_at": rc.ts(NOW)})
    assert r.status_code == 202
    assert bool(checked) is inline


async def _aw(n):
    return n
