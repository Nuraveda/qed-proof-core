"""The credential seam (lane mcp-oauth): a deployment can accept more than API keys, and a limited credential only
reaches the routes its scopes allow. With no resolver, behaviour is exactly the API-key behaviour it always was."""
from __future__ import annotations

from fastapi.testclient import TestClient

from poaw_node.app import Credential, create_app


class FakeStore:
    def __init__(self):
        self.rate_calls: list[str] = []

    async def workspace_for_key(self, key):
        return {"good": "ws-1"}.get(key)

    async def rate_take(self, bucket, *, per_minute):
        self.rate_calls.append(bucket)
        return True

    async def list_connections(self, workspace_id):
        return []

    async def list_claims(self, workspace_id, **kw):
        return []

    async def claim_status(self, workspace_id, claim_id):
        return None


class FakeNode:
    def __init__(self):
        self.store = FakeStore()


def client(credential=None):
    node = FakeNode()

    async def get_node():
        return node

    return TestClient(create_app(get_node, log_id="x", tick_enabled=lambda: False, credential=credential)), node.store


def auth(t):
    return {"Authorization": f"Bearer {t}"}


READ_ROUTES = ["/v1/connections", "/v1/claims", "/v1/claims/c1"]


def test_without_a_resolver_an_api_key_works_everywhere_and_whoami_says_so():
    c, _ = client()
    assert c.get("/v1/connections", headers=auth("good")).status_code == 200
    assert c.get("/v1/whoami", headers=auth("good")).json() == {"workspace_id": "ws-1", "kind": "key", "scopes": None, "audience": None}
    for path in ("/v1/whoami", *READ_ROUTES):
        r = c.get(path, headers=auth("bad"))
        assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer", path
        assert c.get(path).status_code == 401


async def _resolver(token):
    return {"read": Credential("ws-9", frozenset({"claims:read"}), "oauth", "https://mcp.example.test/mcp"),
            "submit": Credential("ws-9", frozenset({"claims:submit"}), "oauth"),
            "none": Credential("ws-9", frozenset(), "oauth")}.get(token)


def test_a_limited_credential_reaches_only_the_routes_its_scopes_allow():
    c, _ = client(_resolver)
    for path in READ_ROUTES:
        assert c.get(path, headers=auth("read")).status_code in (200, 404), path  # 404 = reached the route, claim unknown
        for t in ("submit", "none"):
            r = c.get(path, headers=auth(t))
            assert r.status_code == 403 and "claims:read" in r.json()["detail"], (path, t)
    body = {"action": "x", "target": "y"}
    assert c.post("/v1/claims", json=body, headers=auth("read")).status_code == 403
    assert c.post("/v1/claims", json=body, headers=auth("none")).status_code == 403
    assert c.post("/v1/claims", json=body, headers=auth("submit")).status_code != 403  # past the scope check (the body may still be invalid)


def test_whoami_reports_the_credential_and_any_valid_one_may_ask():
    c, _ = client(_resolver)
    assert c.get("/v1/whoami", headers=auth("read")).json() == {"workspace_id": "ws-9", "kind": "oauth", "scopes": ["claims:read"], "audience": "https://mcp.example.test/mcp"}
    assert c.get("/v1/whoami", headers=auth("none")).status_code == 200
    assert c.get("/v1/whoami", headers=auth("good")).status_code == 401  # the resolver replaces the default: it decides


def test_a_limited_credential_is_rate_limited_by_its_own_hash_not_the_plaintext():
    c, store = client(_resolver)
    c.get("/v1/connections", headers=auth("read"))
    assert store.rate_calls and all(b.startswith("key:") and "read" not in b for b in store.rate_calls)
