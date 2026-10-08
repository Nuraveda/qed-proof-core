"""The anchorer's refusals are the product's integrity guarantee: a fork, a stale root or a blown budget must send NOTHING."""
from datetime import datetime, timedelta, timezone

import poaw_core as p
import pytest
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode

from poaw_node.anchoring import anchor as A

NOW = datetime(2026, 9, 26, 1, 0, tzinfo=timezone.utc)
LEAVES = [p.sha256(bytes([i])) for i in range(12)]


class FakeConn:
    def __init__(self, head_size, last_size, last_at, spent=0, head_root=None, last_root=None, failed_at=None):
        self.head = {"tree_size": head_size, "root_hash": head_root or p.mth(LEAVES[:head_size])}
        self.last = None if last_size is None else {"tree_size": last_size, "root_hash": last_root or p.mth(LEAVES[:last_size]),
                                                    "anchored_at": last_at}
        self.spent, self.failed_at, self.executed = spent, failed_at, []
        self.claim_lost = False

    async def fetchrow(self, sql, *a):
        if "status = 'pending'" in sql:
            return None
        if "status = 'landed'" in sql:
            return self.last
        return self.head

    async def fetchval(self, sql, *a):
        if "insert into qed.anchors" in sql:
            self.executed.append(sql)
            return None if self.claim_lost else 1  # attempts
        return self.failed_at if "status = 'failed'" in sql else self.spent

    async def execute(self, sql, *a):
        self.executed.append(sql)

    async def fetch(self, sql, *a):  # used only by with_nodes, which these tests patch out
        raise AssertionError


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        conn = self.conn

        class Ctx:
            async def __aenter__(self_):
                return conn

            async def __aexit__(self_, *exc):
                return False
        return Ctx()


class NoSendRpc:
    def __init__(self, balance=0, registered=True):
        self.balance, self.registered, self.sent = balance, registered, []

    def call(self, method, *params):
        if method == "eth_getBalance":
            return hex(self.balance)
        if method == "eth_call":  # SchemaRegistry.getSchema, ABI-encoded exactly as the chain returns it (dynamic tuple)
            rec = (b"\x01" * 32, "0x" + "00" * 20, False, A.eth.ANCHOR_SCHEMA) if self.registered else \
                  (b"\x00" * 32, "0x" + "00" * 20, False, "")
            return "0x" + abi_encode(["(bytes32,address,bool,string)"], [rec]).hex()
        raise AssertionError(method)

    def send(self, *a, **k):
        raise AssertionError("must not send")

    def wait(self, *a, **k):
        return None


class SendRpc(NoSendRpc):
    def send(self, signer, chain_id, to, data):
        self.sent.append((chain_id, to, data))
        return "0x" + "ab" * 32


class Signer:
    address = "0x23a848B41db0f152b7B9811e8314B6531dFAe523"


@pytest.fixture
def honest_nodes(monkeypatch):
    async def fake_with_nodes(conn, compute):
        return compute(p.list_view(LEAVES))
    monkeypatch.setattr(A, "with_nodes", fake_with_nodes)


def anchorer(conn, alerts, rpc=None):
    cfg = A.AnchorConfig(chain="eip155:84532", schema_uid=b"\x01" * 32, log_id=b"\x02" * 32)

    async def alert(text):
        alerts.append(text)
    return A.Anchorer(FakePool(conn), signer=Signer(), rpc=rpc or NoSendRpc(), cfg=cfg, ops_alert=alert)


async def test_fork_is_refused_with_p0_and_nothing_sent(honest_nodes):
    alerts = []
    conn = FakeConn(12, 8, NOW - timedelta(hours=1), last_root=p.sha256(b"what we anchored before, rewritten"))
    r = await anchorer(conn, alerts).run(NOW)
    assert r["anchor"] == "refused" and any("P0" in a for a in alerts) and not conn.executed


async def test_stored_root_not_matching_nodes_is_refused(honest_nodes):
    alerts = []
    conn = FakeConn(12, 8, NOW - timedelta(hours=1), head_root=p.sha256(b"tampered head root"))
    r = await anchorer(conn, alerts).run(NOW)
    assert r["anchor"] == "refused" and not conn.executed


async def test_budget_ceiling_pauses_and_alerts(honest_nodes):
    alerts = []
    conn = FakeConn(12, 8, NOW - timedelta(hours=1), spent=10**18)
    r = await anchorer(conn, alerts).run(NOW)
    assert r["anchor"] == "budget-paused" and alerts and not conn.executed


async def test_too_soon_and_nothing_new_skip_quietly(honest_nodes):
    alerts = []
    assert (await anchorer(FakeConn(12, 8, NOW - timedelta(minutes=3)), alerts).run(NOW))["anchor"] == "too-soon"
    assert (await anchorer(FakeConn(8, 8, NOW - timedelta(hours=1)), alerts).run(NOW))["anchor"] == "nothing-new"
    assert not alerts


async def test_unfunded_or_unregistered_sends_nothing_and_alerts_only_on_the_hour(honest_nodes):
    for rpc in (NoSendRpc(balance=0), NoSendRpc(balance=10**18, registered=False)):
        alerts, conn = [], FakeConn(12, 8, NOW - timedelta(hours=1))
        r = await anchorer(conn, alerts, rpc).run(NOW + timedelta(minutes=7))
        assert r["anchor"] == "not-ready" and not conn.executed and not alerts
        r = await anchorer(conn, alerts, rpc).run(NOW)  # minute 0
        assert r["anchor"] == "not-ready" and len(alerts) == 1 and not conn.executed


async def test_recent_failure_backs_off_instead_of_retrying_every_tick(honest_nodes):
    alerts, conn = [], FakeConn(12, 8, NOW - timedelta(hours=1), failed_at=NOW - timedelta(minutes=2))
    assert (await anchorer(conn, alerts, SendRpc(balance=10**18)).run(NOW))["anchor"] == "backoff"
    assert not conn.executed and not alerts


async def test_healthy_path_attests_the_head_over_the_last_anchor(honest_nodes):
    alerts, conn, rpc = [], FakeConn(12, 8, NOW - timedelta(hours=1)), SendRpc(balance=10**18)
    r = await anchorer(conn, alerts, rpc).run(NOW)
    assert r["anchor"] == "sent" and r["tree_size"] == 12 and not alerts
    (chain_id, to, data), = rpc.sent
    assert chain_id == 84532 and to == A.eth.EAS
    ((schema, (_, _, _, _, payload, _)),) = abi_decode(["(bytes32,(address,uint64,bool,bytes32,bytes,uint256))"], data[4:])
    d = A.eth.decode_anchor_data(payload)
    assert schema == b"\x01" * 32 and d["tree_size"] == 12 and d["prev_tree_size"] == 8
    assert d["root_hash"] == p.mth(LEAVES) and d["prev_root_hash"] == p.mth(LEAVES[:8])
    assert len(conn.executed) == 2  # the pending row, then its tx hash


async def test_a_tick_that_loses_the_send_claim_sends_nothing(honest_nodes):
    """#144/#147: an overlapping tick already holds the pending row, so this one must not send a second transaction."""
    alerts, conn, rpc = [], FakeConn(12, 8, NOW - timedelta(hours=1)), SendRpc(balance=10**18)
    conn.claim_lost = True
    r = await anchorer(conn, alerts, rpc).run(NOW)
    assert r["anchor"] == "busy" and not rpc.sent and not alerts


def test_send_claim_never_resets_a_landed_or_pending_row():
    assert "where qed.anchors.status not in ('landed', 'pending')" in A.CLAIM_ANCHOR_SQL
    assert "returning attempts" in A.CLAIM_ANCHOR_SQL


async def test_receipt_before_block_is_visible_defers_quietly_and_lands_next_tick(honest_nodes):
    """Seen live on the first Sepolia anchor: the receipt was served but getBlockByNumber returned null."""
    rc = {"status": "0x1", "blockNumber": "0x10", "gasUsed": "0x5", "effectiveGasPrice": "0x2",
          "logs": [{"address": A.eth.EAS, "topics": [A.eth.ATTESTED_TOPIC], "data": "0x" + "cd" * 32}]}

    class LaggyRpc(SendRpc):
        blocks = [None, {"timestamp": "0x64"}]

        def wait(self, *a, **k):
            return rc

        def call(self, method, *params):
            return self.blocks.pop(0) if method == "eth_getBlockByNumber" else super().call(method, *params)

    class Conn(FakeConn):
        async def fetchrow(self, sql, *a):
            if "where tree_size = $1" in sql:
                return {"tree_size": 12, "tx_hash": "0x" + "ab" * 32}
            return await super().fetchrow(sql, *a)

    alerts, conn, rpc = [], Conn(12, 8, NOW - timedelta(hours=1)), LaggyRpc(balance=10**18)
    a = anchorer(conn, alerts, rpc)
    assert (await a.run(NOW))["anchor"] == "pending" and not alerts
    assert not any("set status = 'landed'" in sql for sql in conn.executed)
    r = await a._land(conn, {"tree_size": 12, "attempts": 1, "tx_hash": "0x" + "ab" * 32}, rc)
    assert r["anchor"] == "landed" and r["uid"] == "0x" + "cd" * 32 and not alerts


# -- #240: a stale poller must not change a newer attempt ---------------------------------------------------------------
def test_reclaiming_a_failed_row_clears_the_old_tx_hash():
    assert "tx_hash = null" in A.CLAIM_ANCHOR_SQL


class RecordingConn(FakeConn):
    async def execute(self, sql, *a):
        self.executed.append((sql, a))
        return "UPDATE 0"  # the row is a newer attempt now, so a guarded update matches nothing


async def test_pollers_are_pinned_to_their_attempt_even_when_tx_hash_is_null(honest_nodes):
    alerts = []
    reverted = {"status": "0x0", "blockNumber": "0x10", "gasUsed": "0x5"}

    class Rpc(NoSendRpc):
        def call(self, method, *params):
            return reverted if method == "eth_getTransactionReceipt" else super().call(method, *params)

    conn = RecordingConn(12, 8, NOW - timedelta(hours=1))
    old = {"tree_size": 12, "attempts": 1, "tx_hash": "0x" + "11" * 32, "created_at": NOW - timedelta(hours=1)}
    assert (await anchorer(conn, alerts, Rpc())._poll(conn, old, NOW))["anchor"] == "stale"
    # a delayed timeout poller of attempt 1 whose tx_hash was null, like the reclaimed attempt 2's
    nohash = {**old, "tx_hash": None}
    assert (await anchorer(conn, alerts, NoSendRpc())._poll(conn, nohash, NOW))["anchor"] == "stale"
    assert not alerts
    for sql, args in conn.executed:
        assert "status = 'pending'" in sql and "attempts = $2" in sql and args[1] == 1


async def test_send_and_wait_lands_with_the_locally_sent_tx_not_a_reread_row(honest_nodes):
    sent_tx = "0x" + "ab" * 32
    rc = {"status": "0x0", "blockNumber": "0x10", "gasUsed": "0x5"}

    class Rpc(SendRpc):
        def wait(self, *a, **k):
            return rc

    class Conn(RecordingConn):
        async def execute(self, sql, *a):
            self.executed.append((sql, a))
            return "UPDATE 1" if "set tx_hash" in sql else "UPDATE 0"  # our tx is recorded, then the row turns out superseded

        async def fetchrow(self, sql, *a):
            if "where tree_size = $1" in sql:
                raise AssertionError("must not re-read the row: it may be a newer attempt with another tx")
            return await super().fetchrow(sql, *a)

    alerts, conn = [], Conn(12, 8, NOW - timedelta(hours=1))
    r = await anchorer(conn, alerts, Rpc(balance=10**18)).run(NOW)
    assert r["anchor"] == "stale" and not alerts   # our attempt was superseded, so the revert is not ours to record


async def test_losing_the_one_pending_index_race_is_busy_not_a_crash(honest_nodes):
    """#147: another tick claimed a different tree size first, so the unique index raises instead of returning no row."""
    class Conn(FakeConn):
        async def fetchval(self, sql, *a):
            if "insert into qed.anchors" in sql:
                raise A.asyncpg.UniqueViolationError("anchors_one_pending")
            return await super().fetchval(sql, *a)

    alerts, conn, rpc = [], Conn(12, 8, NOW - timedelta(hours=1)), SendRpc(balance=10**18)
    r = await anchorer(conn, alerts, rpc).run(NOW)
    assert r["anchor"] == "busy" and not rpc.sent and not alerts
