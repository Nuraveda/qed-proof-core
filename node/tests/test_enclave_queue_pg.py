"""The enclave work-queue SQL against REAL Postgres (lane enclave-verifier): lease_due(skip_enclave), lease_enclave,
count_enclave_pending and queued_claim through the real Store and schema.sql. Needs QED_TEST_PG_URL (CI provides it)."""
import asyncio
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from poaw_node.models import ClaimIn
from poaw_node.store import Store

asyncpg = pytest.importorskip("asyncpg")
URL = os.environ.get("QED_TEST_PG_URL")
pytestmark = pytest.mark.skipif(not URL, reason="QED_TEST_PG_URL not set")

SCHEMA = (Path(__file__).parents[1] / "src" / "poaw_node" / "schema.sql").read_text()
T0 = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
ELIGIBLE = "github.pr.merge"
OTHER = "gmail.message.send"
ACTIONS = [ELIGIBLE]
WINDOW = timedelta(minutes=30)
LEASE = timedelta(minutes=5)


async def _db():
    name = "encq_" + uuid.uuid4().hex[:10]
    admin = await asyncpg.connect(URL)
    await admin.execute(f'create database "{name}"')
    await admin.close()
    base, _, q = URL.partition("?")
    pool = await asyncpg.create_pool(base.rsplit("/", 1)[0] + "/" + name + ("?" + q if q else ""), statement_cache_size=0,
                                     min_size=1, max_size=4)
    await pool.execute(SCHEMA)
    return pool, name


async def _drop(pool, name):
    await pool.close()
    admin = await asyncpg.connect(URL)
    await admin.execute(f'drop database "{name}"')
    await admin.close()


class Seed:
    def __init__(self, store: Store, ws: str):
        self.store, self.ws, self.n = store, ws, 0

    async def add(self, action: str, *, age: timedelta = timedelta(0), decided: bool = False) -> str:
        """Submit a claim, then age it (created_at in the past) and/or mark it decided by writing qed.claims directly."""
        self.n += 1
        claim, _ = await self.store.submit(self.ws, ClaimIn(agent_id="a", client_claim_id=f"c{self.n}", action=action, target="t",
                                                            params={}, claimed_at=T0), claim_digest="d", deadline_at=T0)
        await self.store.pool.execute(
            "update qed.claims set created_at = now() - $2::interval, state = $3 where id = $1::uuid",
            claim.id, age, "decided" if decided else "queued")
        return claim.id


async def _seed(pool) -> Seed:
    ws = await pool.fetchval("insert into qed.workspaces (name) values ('t') returning id::text")
    return Seed(Store(pool), ws)


async def test_lease_due_skip_enclave_leaves_eligible_claims_alone():
    pool, name = await _db()
    try:
        s = await _seed(pool)
        eligible = await s.add(ELIGIBLE)
        other = await s.add(OTHER)
        stale = await s.add(ELIGIBLE, age=WINDOW + timedelta(minutes=1))  # eligible action, but outside the window
        got = {c.id for c in await s.store.lease_due(10, LEASE, skip_enclave=(ACTIONS, WINDOW))}
        assert got == {other, stale}
        assert await pool.fetchval("select attempts from qed.claims where id = $1::uuid", eligible) == 0
        assert await pool.fetchval("select next_attempt_at <= now() from qed.claims where id = $1::uuid", eligible)  # still due
        # without the filter the eligible claim is leased like any other
        assert {c.id for c in await s.store.lease_due(10, LEASE)} == {eligible}
    finally:
        await _drop(pool, name)


async def test_lease_enclave_leases_only_eligible_without_double_leasing():
    pool, name = await _db()
    try:
        s = await _seed(pool)
        ids = {await s.add(ELIGIBLE) for _ in range(6)}
        other = await s.add(OTHER)
        stale = await s.add(ELIGIBLE, age=WINDOW + timedelta(minutes=1))
        decided = await s.add(ELIGIBLE, decided=True)
        not_due = await s.add(ELIGIBLE)
        await pool.execute("update qed.claims set next_attempt_at = now() + interval '1 hour' where id = $1::uuid", not_due)

        assert len(await s.store.lease_enclave(ACTIONS, WINDOW, 2, LEASE)) == 2  # respects limit
        first, second = await asyncio.gather(s.store.lease_enclave(ACTIONS, WINDOW, 4, LEASE),
                                             s.store.lease_enclave(ACTIONS, WINDOW, 4, LEASE))
        a, b = [c.id for c in first], [c.id for c in second]
        assert not set(a) & set(b)  # SKIP LOCKED: never the same claim twice
        assert len(a) + len(b) == 4  # 6 eligible due, 2 already leased
        # the 2 + 4 leased are all eligible; leased claims are not re-leased until the lease expires
        assert await s.store.lease_enclave(ACTIONS, WINDOW, 10, LEASE) == []
        leased = await pool.fetch("select id::text from qed.claims where attempts = 1")
        assert {r["id"] for r in leased} == ids
        for excluded in (other, stale, decided, not_due):
            assert await pool.fetchval("select attempts from qed.claims where id = $1::uuid", excluded) == 0
        await pool.execute("update qed.claims set next_attempt_at = now() - interval '1 second' where id = $1::uuid", a[0])
        again = await s.store.lease_enclave(ACTIONS, WINDOW, 10, LEASE)
        assert [c.id for c in again] == [a[0]] and again[0].attempts == 2
    finally:
        await _drop(pool, name)


async def test_count_enclave_pending_counts_only_queued_eligible_in_window():
    pool, name = await _db()
    try:
        s = await _seed(pool)
        assert await s.store.count_enclave_pending(ACTIONS, WINDOW) == 0
        await s.add(ELIGIBLE)
        await s.add(ELIGIBLE, age=WINDOW - timedelta(minutes=1))
        leased = await s.add(ELIGIBLE)
        await s.add(OTHER)
        await s.add(ELIGIBLE, decided=True)
        await s.add(ELIGIBLE, age=WINDOW + timedelta(minutes=1))
        await pool.execute("update qed.claims set next_attempt_at = now() + interval '1 hour' where id = $1::uuid", leased)
        assert await s.store.count_enclave_pending(ACTIONS, WINDOW) == 3  # queued counts even while leased / not yet due
        assert await s.store.count_enclave_pending([OTHER], WINDOW) == 1
        assert await s.store.count_enclave_pending([], WINDOW) == 0
    finally:
        await _drop(pool, name)


async def test_queued_claim_returns_only_undecided_claims():
    pool, name = await _db()
    try:
        s = await _seed(pool)
        queued = await s.add(ELIGIBLE)
        decided = await s.add(ELIGIBLE, decided=True)
        c = await s.store.queued_claim(queued)
        assert c is not None and c.id == queued and c.action == ELIGIBLE and c.agent_ref == "a" and c.workspace_id == s.ws
        assert await s.store.queued_claim(decided) is None
        assert await s.store.queued_claim(str(uuid.uuid4())) is None
        assert await s.store.queued_claim("not-a-uuid") is None
        assert await s.store.queued_claim("") is None
    finally:
        await _drop(pool, name)
