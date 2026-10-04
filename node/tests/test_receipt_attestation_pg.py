"""A level-3 receipt's attestation document is stored beside the signed body and returned at the receipt's top level
(SPEC §4), against REAL Postgres and schema.sql. Needs QED_TEST_PG_URL (CI provides it)."""
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import poaw_core as p
import pytest

from poaw_node.models import ClaimIn
from poaw_node.store import Store

asyncpg = pytest.importorskip("asyncpg")
URL = os.environ.get("QED_TEST_PG_URL")
pytestmark = pytest.mark.skipif(not URL, reason="QED_TEST_PG_URL not set")

SCHEMA = (Path(__file__).parents[1] / "src" / "poaw_node" / "schema.sql").read_text()
T0 = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)


async def _db():
    name = "attdoc_" + uuid.uuid4().hex[:10]
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


async def _record(store, ws, i, document):
    claim, _ = await store.submit(ws, ClaimIn(agent_id="a", client_claim_id=f"c{i}", action="gmail.message.send", target="t",
                                              params={}, claimed_at=T0), claim_digest="d", deadline_at=T0)
    receipt = {"body": {"receipt_id": f"rcpt_{i}", "verdict": {"value": "verified"}}, "signature": {"alg": "Ed25519"}}
    await store.record(claim, receipt, alert=False, sink="s", attestation_document=document)
    return receipt


async def test_document_is_stored_beside_the_body_and_returned_at_top_level():
    pool, name = await _db()
    try:
        store = Store(pool)
        ws = await pool.fetchval("insert into qed.workspaces (name) values ('t') returning id::text")
        doc = p.b64u(bytes(range(256)) * 24)  # larger than a KMS Ed25519 message
        r3 = await _record(store, ws, 1, doc)
        r1 = await _record(store, ws, 2, None)
        got = await store.receipt_with_proof("rcpt_1", "L")
        assert got["attestation_document"] == doc and got["body"] == r3["body"]
        assert "attestation_document" not in await store.receipt_with_proof("rcpt_2", "L")
        assert p.leaf_hash(got) == p.leaf_hash(r3) and p.leaf_hash(r1)  # the document is outside the leaf
        with pytest.raises(asyncpg.PostgresError, match="append-only"):  # still immutable
            await pool.execute("update qed.receipts set attestation_document = 'x' where id = 'rcpt_1'")
    finally:
        await _drop(pool, name)
