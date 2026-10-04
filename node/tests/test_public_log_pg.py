"""The public log's SQL against REAL Postgres (lane public-log): head/consistency/proof/anchors/entries through the real
Store and schema.sql, and the block fields on a receipt's anchor. Needs QED_TEST_PG_URL (CI provides it and requires this)."""
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import poaw_core as p
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx

from poaw_node.app import create_app
from poaw_node.models import ClaimIn
from poaw_node.store import Store

asyncpg = pytest.importorskip("asyncpg")
URL = os.environ.get("QED_TEST_PG_URL")
pytestmark = pytest.mark.skipif(not URL, reason="QED_TEST_PG_URL not set")

SCHEMA = (Path(__file__).parents[1] / "src" / "poaw_node" / "schema.sql").read_text()
SK = Ed25519PrivateKey.generate()
PK = p.public_key_bytes(SK)
N = 21
T0 = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)


class Client:
    """httpx on the test's own event loop (a sync TestClient would run the app on another loop than the pool's)."""

    def __init__(self, app):
        self.app = app

    async def get(self, path):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://t") as h:
            return await h.get(path)


class Signer:
    def public_key(self):
        return PK

    def sign(self, message):
        return SK.sign(message)


class Node:
    def __init__(self, store):
        self.store, self.signer, self.key_id = store, Signer(), p.key_id(PK)


async def _db():
    name = "publog_" + uuid.uuid4().hex[:10]
    admin = await asyncpg.connect(URL)
    await admin.execute(f'create database "{name}"')
    await admin.close()
    base, _, q = URL.partition("?")
    pool = await asyncpg.create_pool(base.rsplit("/", 1)[0] + "/" + name + ("?" + q if q else ""), statement_cache_size=0,
                                     min_size=1, max_size=3)
    await pool.execute(SCHEMA)
    return pool, name


async def _drop(pool, name):
    await pool.close()
    admin = await asyncpg.connect(URL)
    await admin.execute(f'drop database "{name}"')
    await admin.close()


async def _fill(store: Store):
    ws = await store.pool.fetchval("insert into qed.workspaces (name) values ('t') returning id::text")
    leaves = []
    for i in range(N):
        claim, _ = await store.submit(ws, ClaimIn(agent_id="a", client_claim_id=f"c{i}", action="gmail.message.send", target="t", params={},
                                                  claimed_at=T0), claim_digest="d", deadline_at=T0)
        receipt = {"body": {"receipt_id": f"rcpt_{i}", "verdict": {"value": "verified"}}, "signature": {"alg": "Ed25519"}}
        await store.record(claim, receipt, alert=False, sink="s")
        leaves.append(p.leaf_hash(receipt))
    return leaves


async def test_every_endpoint_over_real_postgres():
    pool, name = await _db()
    try:
        store = Store(pool)
        leaves = await _fill(store)
        for size, uid in [(8, "0xaa"), (16, "0xbb")]:
            await pool.execute(
                """insert into qed.anchors (tree_size, root_hash, chain, tx_hash, eas_uid, block_number, block_time, status)
                   values ($1, $2, 'eip155:84532', '0xtx', $3, $4, $5, 'landed')""",
                size, p.mth(leaves[:size]), uid, 1000 + size, T0)
        await pool.execute("insert into qed.anchors (tree_size, root_hash, chain, status) values (20, $1, 'eip155:84532', 'pending')",
                           p.mth(leaves[:20]))
        node = Node(store)

        async def get_node():
            return node

        c = Client(create_app(get_node, log_id="L", tick_enabled=lambda: False))
        h = (await c.get("/v1/log/head")).json()
        assert p.verify_tree_head(PK, h["tree_head"]["body"], h["tree_head"]["signature"]["value"])
        assert h["tree_head"]["body"]["tree_size"] == N and p.b64u_decode(h["tree_head"]["body"]["root_hash"]) == p.mth(leaves)
        assert h["anchor"]["tree_size"] == 16 and h["anchor"]["block_number"] == 1016  # latest LANDED, not the pending 20
        assert h["anchor"]["block_time"] == "2026-10-04T12:00:00.000Z"

        for m, n in [(1, N), (8, 16), (5, 13), (16, N), (N, N)]:
            j = (await c.get(f"/v1/log/consistency?first={m}&second={n}")).json()
            assert p.verify_consistency(m, n, p.b64u_decode(j["first_root"]), p.b64u_decode(j["second_root"]),
                                        [p.b64u_decode(x) for x in j["proof"]]), (m, n)
            assert p.b64u_decode(j["second_root"]) == p.mth(leaves[:n])

        for i, n in [(0, 1), (3, 8), (9, 16), (20, N)]:
            j = (await c.get(f"/v1/log/proof?leaf_index={i}&tree_size={n}")).json()
            assert p.b64u_decode(j["leaf_hash"]) == leaves[i]
            assert p.root_from_inclusion(i, n, leaves[i], [p.b64u_decode(x) for x in j["inclusion"]]) == p.mth(leaves[:n])
        assert (await c.get(f"/v1/log/proof?leaf_index=0&tree_size={N + 1}")).status_code == 404

        a = (await c.get("/v1/log/anchors")).json()
        assert [x["tree_size"] for x in a["anchors"]] == [16, 8] and a["next"] is None  # pending row hidden
        a1 = (await c.get("/v1/log/anchors?limit=1")).json()
        assert a1["next"] == 16 and (await c.get("/v1/log/anchors?limit=1&before=16")).json()["anchors"][0]["tree_size"] == 8

        e = (await c.get("/v1/log/entries?start=5&limit=10")).json()
        assert [x["leaf_index"] for x in e["entries"]] == list(range(5, 15)) and e["next"] == 15
        assert p.b64u_decode(e["entries"][0]["leaf_hash"]) == leaves[5]
        assert set(e["entries"][0]) == {"leaf_index", "leaf_hash", "created_at"}
        assert (await c.get("/v1/log/entries")).json()["entries"][0]["leaf_index"] == 0  # window = newest 50, log has 21

        r = (await c.get("/v1/receipts/rcpt_3")).json()  # leaf 3 is covered by the size-8 and size-16 anchors: the newer is used
        assert r["proof"]["anchor"]["tree_size"] == 16 and r["proof"]["anchor"]["block_number"] == 1016
        assert r["proof"]["anchor"]["block_time"] == "2026-10-04T12:00:00.000Z"
        assert "anchor" not in (await c.get("/v1/receipts/rcpt_20")).json()["proof"]  # not yet covered by a landed anchor
    finally:
        await _drop(pool, name)


async def test_empty_log_over_real_postgres():
    pool, name = await _db()
    try:
        node = Node(Store(pool))

        async def get_node():
            return node

        c = Client(create_app(get_node, log_id="L", tick_enabled=lambda: False))
        j = (await c.get("/v1/log/head")).json()
        assert j["tree_head"]["body"]["tree_size"] == 0 and j["anchor"] is None
        assert (await c.get("/v1/log/entries")).json() == {"tree_size": 0, "entries": [], "next": None}
    finally:
        await _drop(pool, name)
