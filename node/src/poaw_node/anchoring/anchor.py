"""The anchorer (ADR-003, lane anchoring-base). It runs at the end of each tick.

One anchor in flight at a time. The order of checks is fixed, and every refusal is loud:
  1. A pending anchor → poll its receipt. Landed → record it. Too old → mark failed and alert (the next tick retries).
  2. Nothing new (the tree didn't grow) or too soon (< interval) → skip, quietly.
  3. CONSISTENCY: the new tree must extend the last landed anchor (an RFC 6962 proof). Otherwise → REFUSE + P0 alert, nothing is sent.
  4. BUDGET: today's gas must stay under the daily ceiling. Otherwise → pause + alert.
  5. Attest (root, size, prev) on EAS and record a pending row with the tx hash.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import asyncpg
import poaw_core
from poaw_node.store import with_nodes

from . import eth


# Claims the send for one tree size: a fresh row, or a retry of a FAILED one. A landed or pending row is never reset
# (#144), and the `anchors_one_pending` unique index refuses a second pending row of any size (#147). A retry clears the
# old attempt's tx_hash (#240), so nothing polls the previous transaction on behalf of the new one.
CLAIM_ANCHOR_SQL = """insert into qed.anchors (tree_size, root_hash, prev_tree_size, chain, status, attempts)
   values ($1, $2, $3, $4, 'pending', 1)
   on conflict (tree_size) do update set status = 'pending', attempts = qed.anchors.attempts + 1,
                                         last_error = null, tx_hash = null, created_at = now()
   where qed.anchors.status not in ('landed', 'pending')
   returning attempts"""


# A state change is pinned to the attempt that made it (#240): still pending, same `attempts` number. Every reclaim bumps
# `attempts`, so a stale poller matches no row, even when both attempts have a null tx_hash.
_PINNED = "where tree_size = $1 and status = 'pending' and attempts = $2"


def _changed(result) -> bool:
    return result != "UPDATE 0"  # asyncpg returns the command tag


def log(event: str, **kw) -> None:
    print(json.dumps({"event": event, **kw}, default=str), file=sys.stdout, flush=True)


@dataclass
class AnchorConfig:
    chain: str  # CAIP-2
    schema_uid: bytes
    log_id: bytes  # 32 bytes (the same log_id receipts carry, base64url-decoded)
    interval: timedelta = timedelta(minutes=10)
    daily_max_wei: int = 5 * 10**15  # 0.005 ETH/day ceiling (Sepolia default; set per env)
    pending_timeout: timedelta = timedelta(minutes=10)
    min_balance_wei: int = 5 * 10**12  # ~2 worst-case fee reservations on Base Sepolia (measured 2026-09-25); below this a send would fail

    @property
    def chain_id(self) -> int:
        return int(self.chain.split(":")[1])


class Anchorer:
    def __init__(self, pool, signer: eth.EthSigner, rpc: eth.Rpc, cfg: AnchorConfig, ops_alert):
        self.pool, self.signer, self.rpc, self.cfg, self.ops_alert = pool, signer, rpc, cfg, ops_alert
        self._schema_ok = False

    async def _not_ready(self, now: datetime) -> str | None:
        """Unregistered schema or an unfunded wallet: skip. It's logged every tick and alerted once an hour, never spammed per minute."""
        why = None
        if not self._schema_ok:
            self._schema_ok = await asyncio.to_thread(eth.schema_registered, self.rpc, self.cfg.schema_uid)
            if not self._schema_ok:
                why = "anchor schema is not registered on " + self.cfg.chain
        if why is None:
            bal = int(await asyncio.to_thread(self.rpc.call, "eth_getBalance", self.signer.address, "latest"), 16)
            if bal < self.cfg.min_balance_wei:
                why = f"anchor wallet {self.signer.address} balance {bal} wei is below {self.cfg.min_balance_wei}"
        if why:
            log("anchor.not_ready", reason=why)
            if now.minute == 0:
                await self.ops_alert(f"⚠️ Anchoring is not running: {why}.")
        return why

    async def run(self, now: datetime | None = None) -> dict:
        now = now or datetime.now(timezone.utc)
        try:
            return await self._run(now)
        except Exception as exc:  # the anchorer must never break the tick; it logs and alerts instead
            log("anchor.error", error=type(exc).__name__, detail=str(exc)[:300])
            await self.ops_alert(f"⚠️ Anchorer error: {type(exc).__name__}: {str(exc)[:200]}")
            return {"anchor": "error"}

    async def _run(self, now: datetime) -> dict:
        async with self.pool.acquire() as conn:
            pending = await conn.fetchrow("select * from qed.anchors where status = 'pending' order by tree_size desc limit 1")
            if pending:
                return await self._poll(conn, pending, now)

            last = await conn.fetchrow("select tree_size, root_hash, anchored_at from qed.anchors "
                                       "where status = 'landed' order by tree_size desc limit 1")
            head = await conn.fetchrow("select tree_size, root_hash from qed.log_roots order by tree_size desc limit 1")
            if head is None or (last and head["tree_size"] <= last["tree_size"]):
                return {"anchor": "nothing-new"}
            if last and last["anchored_at"] and now - last["anchored_at"] < self.cfg.interval:
                return {"anchor": "too-soon"}
            failed_at = await conn.fetchval("select max(created_at) from qed.anchors where status = 'failed'")
            if failed_at and now - failed_at < self.cfg.interval:
                return {"anchor": "backoff"}  # a failure was already alerted; retry after one interval, not every minute

            size, root = head["tree_size"], bytes(head["root_hash"])
            prev_size, prev_root = (last["tree_size"], bytes(last["root_hash"])) if last else (0, b"\x00" * 32)
            recomputed = await with_nodes(conn, lambda get: poaw_core.mth_range(0, size, get))
            if recomputed != root:
                return await self._refuse(f"stored root for size {size} does not match the node store")
            if prev_size:
                proof = await with_nodes(conn, lambda get: poaw_core.consistency_proof_nodes(prev_size, size, get))
                if not poaw_core.verify_consistency(prev_size, size, prev_root, root, proof):
                    return await self._refuse(f"tree {size} is NOT an extension of anchored tree {prev_size}")

            spent = await conn.fetchval(
                """select coalesce(sum(gas_used * effective_gas_price_wei), 0) from qed.anchors
                   where status = 'landed' and anchored_at > now() - interval '1 day'""")
            if int(spent) >= self.cfg.daily_max_wei:
                log("anchor.budget_paused", spent_wei=int(spent), ceiling_wei=self.cfg.daily_max_wei)
                await self.ops_alert(f"⏸️ Anchoring paused: daily gas ceiling reached ({int(spent)} wei).")
                return {"anchor": "budget-paused"}

            if why := await self._not_ready(now):
                return {"anchor": "not-ready", "reason": why}

            data = eth.anchor_data(self.cfg.log_id, size, root, prev_size, prev_root, poaw_core.SPEC_VERSION)
            calldata = eth.attest_calldata(self.cfg.schema_uid, data)
            # Claim the send atomically (#144, #147). Ticks can overlap (no reserved concurrency), and a session advisory
            # lock doesn't survive the transaction pooler, so the database decides: a landed or pending row is never reset,
            # and the `anchors_one_pending` unique index allows ONE pending row in total. A tick that loses gets no row back
            # and sends nothing, so two transactions can never race for the same nonce.
            attempt = None
            try:
                attempt = await conn.fetchval(CLAIM_ANCHOR_SQL, size, root, prev_size or None, self.cfg.chain)
            except asyncpg.UniqueViolationError:
                pass  # another tick holds the one pending row: attempt stays None, so this tick is busy
            if attempt is None:
                log("anchor.in_flight_elsewhere", tree_size=size)
                return {"anchor": "busy"}
            try:
                tx = await asyncio.to_thread(self.rpc.send, self.signer, self.cfg.chain_id, eth.EAS, calldata)
            except Exception as exc:
                await conn.execute(f"update qed.anchors set status = 'failed', last_error = $3 {_PINNED}",
                                   size, attempt, f"send: {exc}"[:500])
                log("anchor.send_failed", tree_size=size, error=str(exc)[:200])
                await self.ops_alert(f"❌ Anchor send failed for tree {size}: {str(exc)[:200]}")
                return {"anchor": "send-failed"}
            mine = {"tree_size": size, "attempts": attempt, "tx_hash": tx}  # our own attempt; never re-read, it may have moved on
            if not _changed(await conn.execute(f"update qed.anchors set tx_hash = $3 {_PINNED}", size, attempt, tx)):
                return await self._stale(mine)
            log("anchor.sent", tree_size=size, prev_tree_size=prev_size, tx=tx, chain=self.cfg.chain)
            rc = await asyncio.to_thread(self.rpc.wait, tx, 20)
            if rc:
                return await self._land(conn, mine, rc)
            return {"anchor": "sent", "tree_size": size, "tx": tx}

    async def _poll(self, conn, row, now) -> dict:
        rc = await asyncio.to_thread(self.rpc.call, "eth_getTransactionReceipt", row["tx_hash"]) if row["tx_hash"] else None
        if rc:
            return await self._land(conn, row, rc)
        if now - row["created_at"] > self.cfg.pending_timeout:
            res = await conn.execute(f"update qed.anchors set status = 'failed', last_error = 'not mined before timeout' {_PINNED}",
                                     row["tree_size"], row["attempts"])
            if not _changed(res):
                return await self._stale(row)
            await self.ops_alert(f"❌ Anchor for tree {row['tree_size']} not mined within "
                                 f"{self.cfg.pending_timeout}; it will be retried. tx {row['tx_hash']}")
            return {"anchor": "timed-out", "tree_size": row["tree_size"]}
        return {"anchor": "pending", "tree_size": row["tree_size"]}

    async def _land(self, conn, row, rc) -> dict:
        if int(rc["status"], 16) != 1:
            res = await conn.execute(f"update qed.anchors set status = 'failed', last_error = 'reverted' {_PINNED}",
                                     row["tree_size"], row["attempts"])
            if not _changed(res):
                return await self._stale(row)
            await self.ops_alert(f"❌ Anchor tx REVERTED for tree {row['tree_size']}: {row['tx_hash']}")
            return {"anchor": "reverted"}
        uid = eth.uid_from_receipt(rc)
        block = await asyncio.to_thread(self.rpc.call, "eth_getBlockByNumber", rc["blockNumber"], False)
        if block is None or uid is None:
            # A load-balanced RPC can hand back the receipt before the node serving the next call has the block. The row stays
            # pending with its tx hash, and the next tick's poll lands it. This is not an error, so no alert.
            log("anchor.land_deferred", tree_size=row["tree_size"], block_seen=block is not None, uid_seen=uid is not None)
            return {"anchor": "pending", "tree_size": row["tree_size"]}
        res = await conn.execute(
            """update qed.anchors set status = 'landed', eas_uid = $3, block_number = $4, block_time = to_timestamp($5),
                      gas_used = $6, effective_gas_price_wei = $7, anchored_at = now()
               where tree_size = $1 and status = 'pending' and attempts = $2""",
            row["tree_size"], row["attempts"], uid, int(rc["blockNumber"], 16), int(block["timestamp"], 16),
            int(rc["gasUsed"], 16), int(rc.get("effectiveGasPrice", "0x0"), 16))
        if not _changed(res):
            return await self._stale(row)
        log("anchor.landed", tree_size=row["tree_size"], uid=uid, block=int(rc["blockNumber"], 16),
            gas_used=int(rc["gasUsed"], 16))
        return {"anchor": "landed", "tree_size": row["tree_size"], "uid": uid}

    async def _stale(self, row) -> dict:
        log("anchor.stale_attempt", tree_size=row["tree_size"], tx=row["tx_hash"])
        return {"anchor": "stale", "tree_size": row["tree_size"]}

    async def _refuse(self, why: str) -> dict:
        log("anchor.P0_refused", reason=why)
        await self.ops_alert(f"🚨 P0 Anchoring REFUSED: {why}. Nothing was anchored. Investigate before anything else.")
        return {"anchor": "refused", "reason": why}


def config_from_env(log_id_b64u: str, prefix: str = "POAW_ANCHOR_") -> AnchorConfig | None:
    """Anchoring is off unless <prefix>CHAIN is set (e.g. "eip155:84532" for Base Sepolia)."""
    chain = os.environ.get(f"{prefix}CHAIN")
    if not chain:
        return None
    return AnchorConfig(chain=chain, schema_uid=eth.schema_uid(eth.ANCHOR_SCHEMA), log_id=poaw_core.b64u_decode(log_id_b64u),
                        interval=timedelta(seconds=int(os.environ.get(f"{prefix}INTERVAL_S", "600"))),
                        daily_max_wei=int(os.environ.get(f"{prefix}DAILY_MAX_WEI", str(5 * 10**15))),
                        min_balance_wei=int(os.environ.get(f"{prefix}MIN_BALANCE_WEI", str(5 * 10**12))))
