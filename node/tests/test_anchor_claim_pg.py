"""The anchorer's send claim against REAL Postgres (#144, #147): a landed or pending row is never reset, and only one
pending row can exist, so overlapping ticks can't both send. Needs QED_TEST_PG_URL (CI provides it and requires this test)."""
import os
import re
import uuid
from pathlib import Path

import pytest

from poaw_node.anchoring.anchor import CLAIM_ANCHOR_SQL

asyncpg = pytest.importorskip("asyncpg")
URL = os.environ.get("QED_TEST_PG_URL")
pytestmark = pytest.mark.skipif(not URL, reason="QED_TEST_PG_URL not set")

SCHEMA = (Path(__file__).parents[1] / "src" / "poaw_node" / "schema.sql").read_text()
# The real anchors DDL and its indexes, straight from schema.sql; the FK to log_roots is dropped so the test needs no log.
ANCHORS = re.search(r"create table qed\.anchors \(.*?\n\);", SCHEMA, re.S).group(0).replace(
    " references qed.log_roots(tree_size)", "")
INDEXES = "\n".join(l.split("--")[0] for l in SCHEMA.splitlines() if re.match(r"create (unique )?index \w+ on qed\.anchors", l))
ROOT = b"\x11" * 32


async def _db():
    name = "anchors_" + uuid.uuid4().hex[:10]
    admin = await asyncpg.connect(URL)
    await admin.execute(f'create database "{name}"')
    await admin.close()
    base, _, q = URL.partition("?")
    c = await asyncpg.connect(base.rsplit("/", 1)[0] + "/" + name + ("?" + q if q else ""))
    await c.execute("create schema qed;\n" + ANCHORS + "\n" + INDEXES)
    return c, name


async def _drop(c, name):
    await c.close()
    admin = await asyncpg.connect(URL)
    await admin.execute(f'drop database "{name}"')
    await admin.close()


async def _claim(c, size):
    try:
        return await c.fetchval(CLAIM_ANCHOR_SQL, size, ROOT, None, "eip155:84532")
    except asyncpg.UniqueViolationError:
        return None


async def test_send_claim_is_single_flight_and_never_resets_landed():
    c, name = await _db()
    try:
        assert "anchors_one_pending" in INDEXES
        assert await _claim(c, 8) == 1                 # fresh row → claimed
        assert await _claim(c, 8) is None              # same size already pending → the second tick sends nothing
        assert await _claim(c, 12) is None             # a different size while one is pending → refused by the index
        await c.execute("update qed.anchors set status = 'landed' where tree_size = 8")
        assert await _claim(c, 8) is None              # #144: a landed row is never put back to pending
        assert await c.fetchval("select status from qed.anchors where tree_size = 8") == "landed"
        assert await _claim(c, 12) == 1                # nothing pending now → the next size can be claimed
        await c.execute("update qed.anchors set status = 'failed', tx_hash = '0xold' where tree_size = 12")
        assert await _claim(c, 12) == 2                # a failed row is retried (attempt 2)
        assert await c.fetchval("select attempts from qed.anchors where tree_size = 12") == 2
        assert await c.fetchval("select tx_hash from qed.anchors where tree_size = 12") is None  # #240: no stale tx to poll
    finally:
        await _drop(c, name)


async def test_pinned_update_changes_only_the_attempt_it_polled():
    """#240: a retry bumps `attempts`, so a stale poller's UPDATE matches nothing, even when both attempts have a null tx_hash."""
    from poaw_node.anchoring.anchor import _PINNED
    c, name = await _db()
    try:
        assert await _claim(c, 8) == 1
        await c.execute("update qed.anchors set status = 'failed' where tree_size = 8")   # attempt 1 failed with no tx
        assert await _claim(c, 8) == 2                                   # attempt 2: also no tx
        stale = f"update qed.anchors set status = 'failed', last_error = 'x' {_PINNED}"
        assert await c.execute(stale, 8, 1) == "UPDATE 0"                # the old attempt's poller changes nothing
        assert await c.fetchval("select status from qed.anchors where tree_size = 8") == "pending"
        assert await c.execute(stale, 8, 2) == "UPDATE 1"                # the current attempt can still be failed
    finally:
        await _drop(c, name)
