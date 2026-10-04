"""The free public log API (lane public-log): signed head, consistency, inclusion, anchors, entries, CORS, rate limit.
The store here is an in-memory log built with poaw_core, so every proof the endpoints return is verified with the
independent checker code. The real SQL is covered by test_public_log_pg.py."""
from __future__ import annotations

import pytest
import poaw_core as p
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from poaw_node.app import READS_PER_MIN_PER_IP, create_app

SK = Ed25519PrivateKey.generate()
PK = p.public_key_bytes(SK)
LOG_ID = "log-test"
LEAVES = [p.sha256(b"leaf-%d" % i) for i in range(37)]


class Signer:
    def __init__(self):
        self.calls = 0

    def public_key(self):
        return PK

    def sign(self, message: bytes) -> bytes:
        self.calls += 1
        return SK.sign(message)


class FakeStore:
    def __init__(self, n: int, anchors: list[dict] | None = None):
        self.nodes: dict = {}
        self.leaves = LEAVES[:n]
        for i, leaf in enumerate(self.leaves):
            for lvl, idx, h in p.nodes_completed_by(i, leaf, lambda l, j: self.nodes[(l, j)]):
                self.nodes[(lvl, idx)] = h
        self.anchors = anchors or []
        self.buckets: list[str] = []
        self.allow = 10_000

    def get(self, l, j):
        return self.nodes[(l, j)]

    async def rate_take(self, bucket, *, per_minute):
        self.buckets.append(bucket)
        assert per_minute == READS_PER_MIN_PER_IP
        return len(self.buckets) <= self.allow

    async def workspace_for_key(self, key):
        return None

    async def claim_status(self, ws, cid):
        return None

    async def receipt_with_proof(self, rid, log_id):
        return {"body": {"receipt_id": rid}, "signature": {}, "proof": {}} if rid == "rcpt_x" else None

    async def log_size(self):
        return len(self.leaves)

    async def log_root(self, size):
        return p.mth_range(0, size, self.get)

    async def latest_anchor(self):
        return self.anchors[0] if self.anchors else None

    async def list_anchors(self, limit, before=None):
        rows = [a for a in self.anchors if before is None or a["tree_size"] < before]
        page = rows[:limit]
        return page, (page[-1]["tree_size"] if len(rows) > limit else None)

    async def list_entries(self, start, limit):
        return [{"leaf_index": i, "leaf_hash": p.b64u(self.leaves[i]), "created_at": "2026-10-04T00:00:00.000Z"}
                for i in range(start, min(start + limit, len(self.leaves)))]

    async def log_consistency(self, first, second):
        return (p.mth_range(0, first, self.get), p.mth_range(0, second, self.get),
                p.consistency_proof_nodes(first, second, self.get))

    async def log_inclusion(self, index, size):
        return self.leaves[index], p.mth_range(0, size, self.get), p.inclusion_path_nodes(index, size, self.get)


class FakeNode:
    def __init__(self, store):
        self.store, self.signer = store, Signer()
        self.key_id = p.key_id(PK)


def anchor(size, **kw):
    return {"chain": "eip155:84532", "scheme": "eas", "uid": f"0x{size:064x}", "tx_hash": f"0x{size:x}", "tree_size": size,
            "root_hash": p.b64u(p.mth(LEAVES[:size])), "block_number": 100 + size, "block_time": "2026-10-04T01:00:00.000Z"} | kw


def make(n=37, anchors=None):
    store = FakeStore(n, anchors)
    node = FakeNode(store)

    async def get_node():
        return node

    return TestClient(create_app(get_node, log_id=LOG_ID, tick_enabled=lambda: False)), store, node


def b(x):
    return p.b64u_decode(x)


# -- head ------------------------------------------------------------------------------------------------------------
def test_head_signature_verifies_and_matches_the_tree():
    c, _, node = make(anchors=[anchor(32)])
    r = c.get("/v1/log/head")
    assert r.status_code == 200
    j = r.json()
    body, sig = j["tree_head"]["body"], j["tree_head"]["signature"]
    assert body["log_id"] == LOG_ID and body["tree_size"] == 37
    assert b(body["root_hash"]) == p.mth(LEAVES)
    assert sig["alg"] == "Ed25519" and sig["key_id"] == node.key_id
    assert p.verify_tree_head(PK, body, sig["value"])
    assert not p.verify_signature(PK, body, sig["value"])  # not a receipt signature
    assert j["anchor"]["tree_size"] == 32 and j["anchor"]["block_number"] == 132 and j["anchor"]["block_time"]


def test_head_without_anchor_is_null_and_signature_is_cached_per_size():
    c, store, node = make()
    first = c.get("/v1/log/head").json()
    assert first["anchor"] is None
    again = c.get("/v1/log/head").json()
    assert again["tree_head"] == first["tree_head"] and node.signer.calls == 1  # no re-sign for the same size
    store.leaves.append(LEAVES[0])  # size changes -> a new head is signed
    store.nodes.clear()
    for i, leaf in enumerate(store.leaves):
        for lvl, idx, h in p.nodes_completed_by(i, leaf, lambda l, j: store.nodes[(l, j)]):
            store.nodes[(lvl, idx)] = h
    third = c.get("/v1/log/head").json()["tree_head"]
    assert third["body"]["tree_size"] == 38 and node.signer.calls == 2
    assert p.verify_tree_head(PK, third["body"], third["signature"]["value"])


def test_empty_log_serves_a_signed_size_zero_head_with_the_rfc6962_empty_root():
    c, _, _ = make(0)
    j = c.get("/v1/log/head").json()
    body = j["tree_head"]["body"]
    assert body["tree_size"] == 0 and b(body["root_hash"]) == p.sha256(b"")
    assert p.verify_tree_head(PK, body, j["tree_head"]["signature"]["value"]) and j["anchor"] is None


# -- consistency -----------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("m,n", [(1, 2), (3, 7), (8, 8), (5, 32), (13, 37), (1, 37), (36, 37)])
def test_consistency_proof_verifies(m, n):
    c, _, _ = make()
    j = c.get(f"/v1/log/consistency?first={m}&second={n}").json()
    assert (j["log_id"], j["first"], j["second"]) == (LOG_ID, m, n)
    assert b(j["first_root"]) == p.mth(LEAVES[:m]) and b(j["second_root"]) == p.mth(LEAVES[:n])
    proof = [b(x) for x in j["proof"]]
    assert p.verify_consistency(m, n, b(j["first_root"]), b(j["second_root"]), proof)
    assert (m == n) == (proof == [])
    if m < n:
        assert not p.verify_consistency(m, n, p.sha256(b"forged"), b(j["second_root"]), proof)


@pytest.mark.parametrize("q,code", [("first=0&second=5", 400), ("first=5&second=3", 400), ("first=-1&second=3", 400),
                                    ("first=x&second=3", 400), ("first=3", 400), ("", 400),
                                    ("first=3&second=38", 404), ("first=40&second=40", 404)])
def test_consistency_bad_params(q, code):
    c, _, _ = make()
    assert c.get(f"/v1/log/consistency?{q}").status_code == code


# -- inclusion -------------------------------------------------------------------------------------------------------
def test_proof_at_an_older_size_verifies_against_that_sizes_root():
    c, _, _ = make()
    for i, n in [(0, 1), (4, 9), (8, 9), (20, 24), (36, 37)]:
        j = c.get(f"/v1/log/proof?leaf_index={i}&tree_size={n}").json()
        assert (j["leaf_index"], j["tree_size"], j["log_id"]) == (i, n, LOG_ID)
        assert b(j["leaf_hash"]) == LEAVES[i] and b(j["root_hash"]) == p.mth(LEAVES[:n])
        assert p.root_from_inclusion(i, n, b(j["leaf_hash"]), [b(x) for x in j["inclusion"]]) == b(j["root_hash"])


def test_proof_defaults_to_current_size():
    c, _, _ = make()
    j = c.get("/v1/log/proof?leaf_index=3").json()
    assert j["tree_size"] == 37 and b(j["root_hash"]) == p.mth(LEAVES)


@pytest.mark.parametrize("q,code", [("leaf_index=-1", 400), ("leaf_index=x", 400), ("", 400), ("leaf_index=1&tree_size=0", 400),
                                    ("leaf_index=5&tree_size=5", 404), ("leaf_index=37", 404),
                                    ("leaf_index=1&tree_size=38", 404)])
def test_proof_bad_params(q, code):
    c, _, _ = make()
    assert c.get(f"/v1/log/proof?{q}").status_code == code


# -- anchors ---------------------------------------------------------------------------------------------------------
def test_anchors_newest_first_and_paginate():
    c, _, _ = make(anchors=[anchor(s) for s in (36, 30, 24, 16, 8)])
    page1 = c.get("/v1/log/anchors?limit=2").json()
    assert [a["tree_size"] for a in page1["anchors"]] == [36, 30] and page1["next"] == 30
    page2 = c.get(f"/v1/log/anchors?limit=2&before={page1['next']}").json()
    assert [a["tree_size"] for a in page2["anchors"]] == [24, 16] and page2["next"] == 16
    page3 = c.get(f"/v1/log/anchors?limit=2&before={page2['next']}").json()
    assert [a["tree_size"] for a in page3["anchors"]] == [8] and page3["next"] is None
    assert c.get("/v1/log/anchors").json()["next"] is None  # default limit 20 covers all five
    assert set(page1["anchors"][0]) == {"chain", "scheme", "uid", "tx_hash", "tree_size", "root_hash", "block_number", "block_time"}


@pytest.mark.parametrize("q", ["limit=0", "limit=101", "limit=x", "before=0", "before=x"])
def test_anchors_bad_params(q):
    c, _, _ = make()
    assert c.get(f"/v1/log/anchors?{q}").status_code == 400


# -- entries ---------------------------------------------------------------------------------------------------------
def test_entries_default_window_is_the_newest_50_and_ascending():
    c, _, _ = make()
    j = c.get("/v1/log/entries").json()
    assert j["tree_size"] == 37 and [e["leaf_index"] for e in j["entries"]] == list(range(37)) and j["next"] is None
    assert set(j["entries"][0]) == {"leaf_index", "leaf_hash", "created_at"}  # hashes only, no receipt ids


def test_entries_paginate_with_next():
    c, _, _ = make()
    seen, nxt = [], 0
    while nxt is not None:
        j = c.get(f"/v1/log/entries?start={nxt}&limit=10").json()
        seen += [e["leaf_index"] for e in j["entries"]]
        nxt = j["next"]
    assert seen == list(range(37))
    assert c.get("/v1/log/entries?start=30&limit=3").json()["next"] == 33
    assert c.get("/v1/log/entries?start=37").json() == {"tree_size": 37, "entries": [], "next": None}


def test_entries_bounds():
    c, _, _ = make()
    assert c.get("/v1/log/entries?start=38").status_code == 404
    for q in ("limit=0", "limit=101", "start=-1", "start=x"):
        assert c.get(f"/v1/log/entries?{q}").status_code == 400, q
    assert len(c.get("/v1/log/entries?start=0&limit=100").json()["entries"]) == 37


# -- rate limit + CORS ---------------------------------------------------------------------------------------------
PUBLIC = ["/v1/log/head", "/v1/log/consistency?first=1&second=2", "/v1/log/proof?leaf_index=0", "/v1/log/anchors",
          "/v1/log/entries", "/v1/receipts/rcpt_x"]


@pytest.mark.parametrize("path", PUBLIC)
def test_public_reads_need_no_auth_use_the_ip_bucket_and_are_rate_limited(path):
    c, store, _ = make()
    r = c.get(path)
    assert r.status_code == 200 and store.buckets and all(x.startswith("ip:") for x in store.buckets)
    store.allow = len(store.buckets)  # the next call is over the limit
    limited = c.get(path)
    assert limited.status_code == 429 and limited.headers["retry-after"]
    assert limited.headers["access-control-allow-origin"] == "*"  # a browser can read the 429 too


@pytest.mark.parametrize("path", PUBLIC)
def test_public_gets_allow_any_origin_without_credentials(path):
    c, _, _ = make()
    r = c.get(path, headers={"Origin": "https://example.org"})
    assert r.headers["access-control-allow-origin"] == "*"
    assert "access-control-allow-credentials" not in r.headers


@pytest.mark.parametrize("path", PUBLIC)
def test_preflight_works_from_any_origin(path):
    c, store, _ = make()
    r = c.options(path, headers={"Origin": "https://example.org", "Access-Control-Request-Method": "GET",
                                 "Access-Control-Request-Headers": "authorization"})
    assert r.status_code == 204 and r.headers["access-control-allow-origin"] == "*"
    assert "GET" in r.headers["access-control-allow-methods"] and "POST" not in r.headers["access-control-allow-methods"]
    assert "authorization" in r.headers["access-control-allow-headers"].lower()
    assert "access-control-allow-credentials" not in r.headers
    assert store.buckets == []  # a preflight costs no read budget


@pytest.mark.parametrize("method,path", [("get", "/v1/whoami"), ("get", "/v1/claims"), ("get", "/v1/connections"),
                                         ("get", "/v1/claims/abc"), ("post", "/v1/claims"), ("get", "/healthz")])
def test_no_cors_on_authenticated_or_write_routes(method, path):
    c, _, _ = make()
    r = getattr(c, method)(path, headers={"Origin": "https://example.org"})
    assert "access-control-allow-origin" not in r.headers
    pre = c.options(path, headers={"Origin": "https://example.org", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in pre.headers


def test_outermost_public_cors_beats_a_deployments_allow_list():
    """The hosted API adds an exact-origin CORSMiddleware for its console, then PublicCors outside it (lambda_app)."""
    from fastapi.middleware.cors import CORSMiddleware
    from poaw_node.app import PublicCors

    _, store, node = make()

    async def get_node():
        return node

    app = create_app(get_node, log_id=LOG_ID, tick_enabled=lambda: False)
    app.add_middleware(CORSMiddleware, allow_origins=["https://console.example"], allow_credentials=False,
                       allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])
    app.add_middleware(PublicCors)
    c = TestClient(app)
    foreign = {"Origin": "https://example.org", "Access-Control-Request-Method": "GET"}
    assert c.options("/v1/log/head", headers=foreign).headers["access-control-allow-origin"] == "*"
    assert c.get("/v1/log/head", headers={"Origin": "https://console.example"}).headers["access-control-allow-origin"] == "*"
    assert c.options("/v1/claims", headers=foreign | {"Access-Control-Request-Method": "POST"}).status_code == 400  # allow-list intact
    assert "access-control-allow-origin" not in c.get("/v1/claims", headers={"Origin": "https://example.org"}).headers
