"""Postgres access (schema `qed`). Plain SQL, no ORM (ADR-008). Built for a transaction-mode pooler: no session state,
no prepared-statement cache (the caller creates the pool with statement_cache_size=0).

Leaf indexes are gapless: appends take a transaction-scoped advisory lock. Receipts, leaves and roots are append-only
(DB triggers). This module never issues UPDATE or DELETE against them.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import asyncpg
import poaw_core

from .models import Claim, ClaimIn
from .receipt import ts

LOG_LOCK = 0x51ED_0001  # advisory lock key for log appends

# GET /v1/connections. Only columns needed to route a claim: never an account name, login, team/user id or secret_ref
# (lane connections-list-api, "data minimisation"). Active rows only, oldest first.
LIST_CONNECTIONS_SQL = """select id::text as id, provider, scopes, created_at from qed.connections
   where workspace_id = $1::uuid and status = 'active'
   order by created_at, id"""


def key_hash(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def _claim(r: asyncpg.Record) -> Claim:
    return Claim(id=str(r["id"]), workspace_id=str(r["workspace_id"]), agent_ref=r["agent_ref"],
                 client_claim_id=r["client_claim_id"], action=r["action"], target=r["target"],
                 params=json.loads(r["params"]) if isinstance(r["params"], str) else dict(r["params"]),
                 claimed_at=r["claimed_at"], deadline_at=r["deadline_at"], attempts=r["attempts"])


_CLAIM_COLS = """c.id, c.workspace_id, a.external_ref as agent_ref, c.client_claim_id, c.action, c.target, c.params,
                 c.claimed_at, c.deadline_at, c.attempts"""


class Store:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def rate_take(self, bucket: str, *, per_minute: int) -> bool:
        """True if the request is allowed. On a limiter error it FAILS OPEN and logs (SECURITY F2 decision)."""
        try:
            left = await self.pool.fetchval("select qed.rate_take($1, $2, $3)", bucket, float(per_minute), per_minute / 60.0)
            return left >= 0
        except Exception as exc:
            import json, sys
            print(json.dumps({"event": "ratelimit.error", "error": type(exc).__name__}), file=sys.stdout, flush=True)
            return True

    async def installation_for(self, workspace_id: str, provider: str = "github") -> int | None:
        """The ACTIVE installation bound to THIS workspace, or None. Scoped by workspace, so there's no cross-tenant path."""
        return await self.pool.fetchval(
            """select installation_id from qed.connections
               where workspace_id = $1::uuid and provider = $2 and status = 'active' and installation_id is not null""",
            workspace_id, provider)

    async def workspace_for_key(self, api_key: str) -> str | None:
        return await self.pool.fetchval(
            "select workspace_id::text from qed.api_keys where key_hash = $1 and revoked_at is null", key_hash(api_key))

    async def submit(self, workspace_id: str, c: ClaimIn, *, claim_digest: str, deadline_at: datetime) -> tuple[Claim, bool]:
        """Insert idempotently on (workspace, client_claim_id). Returns (claim, created)."""
        async with self.pool.acquire() as conn, conn.transaction():
            agent_id = await conn.fetchval(
                """insert into qed.agents (workspace_id, external_ref) values ($1, $2)
                   on conflict (workspace_id, external_ref) do update set external_ref = excluded.external_ref
                   returning id""", workspace_id, c.agent_id)
            new_id = await conn.fetchval(
                """insert into qed.claims (workspace_id, agent_id, client_claim_id, action, target, params, claimed_at,
                                           claim_digest, deadline_at)
                   values ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9)
                   on conflict (workspace_id, client_claim_id) do nothing returning id""",
                workspace_id, agent_id, c.client_claim_id, c.action, c.target, json.dumps(c.params), c.claimed_at,
                claim_digest, deadline_at)
            row = await conn.fetchrow(
                f"select {_CLAIM_COLS} from qed.claims c join qed.agents a on a.id = c.agent_id "
                "where c.workspace_id = $1 and c.client_claim_id = $2", workspace_id, c.client_claim_id)
            return _claim(row), new_id is not None

    async def lease_due(self, limit: int, lease: timedelta) -> list[Claim]:
        """Claim up to `limit` due claims for this worker (the SKIP LOCKED lease pattern)."""
        rows = await self.pool.fetch(
            f"""with due as (
                   select id from qed.claims where state = 'queued' and next_attempt_at <= now()
                   order by next_attempt_at limit $1 for update skip locked)
                update qed.claims c set next_attempt_at = now() + $2::interval, attempts = c.attempts + 1
                from due, qed.agents a where c.id = due.id and a.id = c.agent_id
                returning {_CLAIM_COLS}""", limit, lease)
        return [_claim(r) for r in rows]

    async def bump_attempt(self, claim_id: str) -> int:
        return await self.pool.fetchval(
            "update qed.claims set attempts = attempts + 1 where id = $1 returning attempts", claim_id)

    async def reschedule(self, claim_id: str, next_at: datetime, error: str) -> None:
        await self.pool.execute(
            "update qed.claims set next_attempt_at = $2, last_error = $3 where id = $1 and state = 'queued'",
            claim_id, next_at, error[:500])

    async def record(self, claim: Claim, receipt: dict, *, alert: bool, sink: str) -> int:
        """Append the signed receipt to the log and mark the claim decided, atomically. Returns leaf_index."""
        leaf = poaw_core.leaf_hash(receipt)
        async with self.pool.acquire() as conn, conn.transaction():
            await conn.execute("select pg_advisory_xact_lock($1)", LOG_LOCK)
            already = await conn.fetchval("select id from qed.receipts where claim_id = $1", claim.id)
            if already:
                return await conn.fetchval("select leaf_index from qed.receipts where id = $1", already)
            idx = await conn.fetchval("select coalesce(max(leaf_index) + 1, 0) from qed.log_leaves")
            await conn.execute("insert into qed.log_leaves (leaf_index, leaf_hash, receipt_id) values ($1, $2, $3)",
                               idx, leaf, receipt["body"]["receipt_id"])
            new_nodes = await with_nodes(conn, lambda get: poaw_core.nodes_completed_by(idx, leaf, get)[1:])
            await conn.executemany("insert into qed.log_nodes (level, idx, hash) values ($1, $2, $3)",
                                   [(0, idx, leaf)] + list(new_nodes))
            await conn.execute(
                """insert into qed.receipts (id, claim_id, workspace_id, body, signature, leaf_index, verdict)
                   values ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7)""",
                receipt["body"]["receipt_id"], claim.id, claim.workspace_id, json.dumps(receipt["body"]),
                json.dumps(receipt["signature"]), idx, receipt["body"]["verdict"]["value"])
            await conn.execute("update qed.claims set state = 'decided' where id = $1", claim.id)
            size = idx + 1
            root = await with_nodes(conn, lambda get: poaw_core.mth_range(0, size, get))
            await conn.execute("insert into qed.log_roots (tree_size, root_hash) values ($1, $2) on conflict do nothing",
                               size, root)
            if alert:
                await conn.execute("insert into qed.alerts (receipt_id, sink) values ($1, $2)",
                                   receipt["body"]["receipt_id"], sink)
            return idx

    async def claim_status(self, workspace_id: str, claim_id: str) -> dict[str, Any] | None:
        r = await self.pool.fetchrow(
            """select c.id::text as claim_id, c.state, c.attempts, r.id as receipt_id, r.verdict
               from qed.claims c left join qed.receipts r on r.claim_id = c.id
               where c.id = $1::uuid and c.workspace_id = $2::uuid""", claim_id, workspace_id)
        return dict(r) if r else None

    async def list_claims(self, workspace_id: str, *, limit: int, before: tuple[datetime, str] | None = None,
                          agent_id: str | None = None, action: str | None = None, verdict: str | None = None,
                          state: str | None = None) -> list[dict[str, Any]]:
        """Newest-first (created_at desc, id desc), for GET /v1/claims. Each row carries the same columns as
        `claim_status` (SPEC parity) plus `created_at`/`claim_id` for the caller to build a keyset cursor from the
        last row. `limit` should be requested as (page size + 1) so the caller can tell whether more pages exist."""
        conds = ["c.workspace_id = $1::uuid"]
        args: list[Any] = [workspace_id]
        if before is not None:
            args.append(before[0])
            args.append(before[1])
            conds.append(f"(c.created_at, c.id) < (${len(args) - 1}::timestamptz, ${len(args)}::uuid)")
        if agent_id is not None:
            args.append(agent_id)
            conds.append(f"a.external_ref = ${len(args)}")
        if action is not None:
            args.append(action)
            conds.append(f"c.action = ${len(args)}")
        if verdict is not None:
            args.append(verdict)
            conds.append(f"r.verdict = ${len(args)}")
        if state is not None:
            args.append(state)
            conds.append(f"c.state = ${len(args)}")
        args.append(limit)
        rows = await self.pool.fetch(
            f"""select c.id::text as claim_id, c.state, c.attempts, r.id as receipt_id, r.verdict, c.created_at
                from qed.claims c join qed.agents a on a.id = c.agent_id left join qed.receipts r on r.claim_id = c.id
                where {' and '.join(conds)}
                order by c.created_at desc, c.id desc
                limit ${len(args)}""", *args)
        return [dict(r) for r in rows]

    async def list_connections(self, workspace_id: str) -> list[dict[str, Any]]:
        """The workspace's active connections for GET /v1/connections (see LIST_CONNECTIONS_SQL)."""
        return [dict(r) for r in await self.pool.fetch(LIST_CONNECTIONS_SQL, workspace_id)]

    async def receipt_with_proof(self, receipt_id: str, log_id: str) -> dict | None:
        r = await self.pool.fetchrow("select body, signature, leaf_index from qed.receipts where id = $1", receipt_id)
        if not r:
            return None
        body = json.loads(r["body"]) if isinstance(r["body"], str) else r["body"]
        sig = json.loads(r["signature"]) if isinstance(r["signature"], str) else r["signature"]
        i = r["leaf_index"]
        async with self.pool.acquire() as conn:
            # Prove against the latest ANCHORED size that covers this leaf, if there is one (so the proof links to the
            # chain). Otherwise use the current size.
            anchor = await conn.fetchrow(
                """select tree_size, chain, eas_uid, tx_hash, block_number, block_time from qed.anchors
                   where status = 'landed' and tree_size > $1 order by tree_size desc limit 1""", i)
            size = anchor["tree_size"] if anchor else await conn.fetchval("select max(tree_size) from qed.log_roots")
            root, path = await with_nodes(conn, lambda get: (poaw_core.mth_range(0, size, get),
                                                             poaw_core.inclusion_path_nodes(i, size, get)))
        proof = {"log_id": log_id, "leaf_index": i, "tree_size": size, "root_hash": poaw_core.b64u(root),
                 "inclusion": [poaw_core.b64u(h) for h in path]}
        if anchor:
            proof["anchor"] = {"chain": anchor["chain"], "scheme": "eas", "uid": anchor["eas_uid"],
                               "tx_hash": anchor["tx_hash"], "tree_size": anchor["tree_size"],
                               "block_number": anchor["block_number"],
                               "block_time": ts(anchor["block_time"]) if anchor["block_time"] else None}
        return {"body": body, "signature": sig, "proof": proof}

    # -- public log reads (lane public-log). Hashes only: no receipt ids, no bodies. ---------------------------------
    async def log_size(self) -> int:
        return await self.pool.fetchval("select coalesce(max(tree_size), 0) from qed.log_roots")

    async def log_root(self, size: int) -> bytes | None:
        r = await self.pool.fetchval("select root_hash from qed.log_roots where tree_size = $1", size)
        return bytes(r) if r is not None else None

    @staticmethod
    def _anchor_json(a: asyncpg.Record) -> dict:
        return {"chain": a["chain"], "scheme": "eas", "uid": a["eas_uid"], "tx_hash": a["tx_hash"],
                "tree_size": a["tree_size"], "root_hash": poaw_core.b64u(bytes(a["root_hash"])),
                "block_number": a["block_number"], "block_time": ts(a["block_time"]) if a["block_time"] else None}

    async def list_anchors(self, limit: int, before: int | None = None) -> tuple[list[dict], int | None]:
        """Landed anchors, newest first. Returns (page, next) where `next` is the `before` value for the following page."""
        rows = await self.pool.fetch(
            """select tree_size, root_hash, chain, eas_uid, tx_hash, block_number, block_time from qed.anchors
               where status = 'landed' and ($2::bigint is null or tree_size < $2) order by tree_size desc limit $1""",
            limit + 1, before)
        page = [self._anchor_json(r) for r in rows[:limit]]
        return page, (page[-1]["tree_size"] if len(rows) > limit else None)

    async def latest_anchor(self) -> dict | None:
        page, _ = await self.list_anchors(1)
        return page[0] if page else None

    async def list_entries(self, start: int, limit: int) -> list[dict]:
        rows = await self.pool.fetch(
            "select leaf_index, leaf_hash, created_at from qed.log_leaves where leaf_index >= $1 "
            "order by leaf_index limit $2", start, limit)
        return [{"leaf_index": r["leaf_index"], "leaf_hash": poaw_core.b64u(bytes(r["leaf_hash"])),
                 "created_at": ts(r["created_at"])} for r in rows]

    async def log_consistency(self, first: int, second: int) -> tuple[bytes, bytes, list[bytes]]:
        """(root of the first-size tree, root of the second-size tree, RFC 6962 consistency proof). 0 < first <= second."""
        async with self.pool.acquire() as conn:
            return await with_nodes(conn, lambda get: (poaw_core.mth_range(0, first, get),
                                                       poaw_core.mth_range(0, second, get),
                                                       poaw_core.consistency_proof_nodes(first, second, get)))

    async def log_inclusion(self, index: int, size: int) -> tuple[bytes, bytes, list[bytes]]:
        """(leaf hash, root of the size-`size` tree, inclusion path). index < size."""
        async with self.pool.acquire() as conn:
            leaf = await conn.fetchval("select leaf_hash from qed.log_leaves where leaf_index = $1", index)
            root, path = await with_nodes(conn, lambda get: (poaw_core.mth_range(0, size, get),
                                                             poaw_core.inclusion_path_nodes(index, size, get)))
        return bytes(leaf), root, path

    async def pending_alerts(self, limit: int = 20) -> list[dict]:
        rows = await self.pool.fetch(
            """select a.id::text, r.body, r.signature, r.workspace_id::text as workspace_id
               from qed.alerts a join qed.receipts r on r.id = a.receipt_id
               where a.status = 'pending' and a.attempts < 5 order by a.created_at limit $1""", limit)
        out = []
        for x in rows:
            body = json.loads(x["body"]) if isinstance(x["body"], str) else x["body"]
            out.append({"alert_id": x["id"], "workspace_id": x["workspace_id"], "receipt": {"body": body}})
        return out

    async def mark_alert(self, alert_id: str, ok: bool, error: str = "") -> None:
        await self.pool.execute(
            """update qed.alerts set status = case when $2 then 'sent' when attempts + 1 >= 5 then 'failed' else 'pending' end,
                      attempts = attempts + 1, sent_at = case when $2 then now() end, last_error = nullif($3, '')
               where id = $1::uuid""", alert_id, ok, error[:500])


async def with_nodes(conn, compute):
    """Run `compute(get_node)` over qed.log_nodes, reading ONLY the nodes it needs (#22).

    The proof algorithms' control flow depends on sizes and indexes, never on hash values. So pass 1 runs with a recording
    getter to learn which (level, idx) nodes are needed, one query fetches them, and pass 2 computes for real."""
    wanted: set[tuple[int, int]] = set()

    def record(level: int, idx: int) -> bytes:
        wanted.add((level, idx))
        return b"\x00" * 32

    compute(record)
    rows = await conn.fetch(
        "select level, idx, hash from qed.log_nodes where (level, idx) in (select * from unnest($1::smallint[], $2::bigint[]))",
        [l for l, _ in wanted], [i for _, i in wanted])
    got = {(r["level"], r["idx"]): bytes(r["hash"]) for r in rows}
    missing = wanted - got.keys()
    if missing:
        raise RuntimeError(f"log_nodes missing {len(missing)} node(s), e.g. {sorted(missing)[:3]}. Run scripts/backfill_log_nodes.py")
    return compute(lambda level, idx: got[(level, idx)])


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
