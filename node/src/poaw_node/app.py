"""HTTP surface (ARCHITECTURE §3). The app is built from a Node, so deployments inject their own seams."""
from __future__ import annotations

import base64
import binascii
import re
from datetime import datetime, timezone
from typing import Awaitable, Callable, NamedTuple

import poaw_core
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError

from pydantic import ValidationError

from .models import ClaimIn
from .receipt import ts
from .store import key_hash
from .service import Node
from .verifiers import REGISTRY, load_builtin


CLAIMS_PER_MIN_PER_KEY = 60
READS_PER_MIN_PER_IP = 120
LIST_CLAIMS_DEFAULT_LIMIT = 50
LIST_CLAIMS_MAX_LIMIT = 200
LOG_PAGE_MAX = 100
ENTRIES_DEFAULT_LIMIT = 50
ANCHORS_DEFAULT_LIMIT = 20
MAX_BODY_BYTES = 64 * 1024


def _encode_cursor(created_at: datetime, claim_id: str) -> str:
    raw = f"{created_at.isoformat()}|{claim_id}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        ts_str, sep, claim_id = raw.partition("|")
        if not sep or not claim_id:
            raise ValueError("malformed cursor")
        return datetime.fromisoformat(ts_str), claim_id
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="invalid cursor") from None

class _BodyCap:
    """ASGI wrapper: read the body up front and refuse it once it passes `limit` bytes (#143). The Content-Length check in
    `harden` can't see a chunked body, so this counts what actually arrives. Bodies here are small, so it buffers the
    allowed ones and replays them to the app."""

    def __init__(self, app, limit: int = MAX_BODY_BYTES):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks, total, more = [], 0, True
        while more:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return
            body = msg.get("body", b"")
            total += len(body)
            if total > self.limit:
                from fastapi.responses import JSONResponse
                resp = JSONResponse({"detail": "request body too large"}, status_code=413,
                                    headers=SECURITY_HEADERS | {"Connection": "close"})
                return await resp(scope, receive, send)
            chunks.append(body)
            more = msg.get("more_body", False)
        replayed = False

        async def replay():
            nonlocal replayed
            if replayed:
                return await receive()
            replayed = True
            return {"type": "http.request", "body": b"".join(chunks), "more_body": False}

        return await self.app(scope, replay, send)


SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


# Free public reads (lane public-log): the log, a receipt, and the key set need no key and answer cross-origin GETs from
# any site, with no credentials. Nothing authenticated or write-capable matches this pattern.
PUBLIC_READ_PATH = re.compile(r"^/(v1/log/(head|consistency|proof|anchors|entries)|v1/receipts/[^/]+|\.well-known/poaw-keys\.json)$")


class PublicCors:
    """ASGI middleware: `Access-Control-Allow-Origin: *` on the public read paths only, and a preflight answer for them.
    Deployments that add an allow-list CORSMiddleware for their own web app should wrap THIS outside it, so a preflight
    from any origin reaches these paths."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not PUBLIC_READ_PATH.match(scope["path"]):
            return await self.app(scope, receive, send)
        if scope["method"] == "OPTIONS":
            from fastapi.responses import Response
            req = dict(scope["headers"])
            if b"origin" not in req:
                return await self.app(scope, receive, send)
            resp = Response(status_code=204, headers={
                "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
                "Access-Control-Allow-Headers": "Authorization, Content-Type", "Access-Control-Max-Age": "600",
                "Vary": "Origin"} | SECURITY_HEADERS)
            return await resp(scope, receive, send)

        async def wrapped(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message["headers"]
                           if k.lower() not in (b"access-control-allow-origin", b"access-control-allow-credentials")]
                headers += [(b"access-control-allow-origin", b"*"), (b"access-control-expose-headers", b"Retry-After")]
                message = {**message, "headers": headers}
            await send(message)

        return await self.app(scope, receive, wrapped)


EDGE_IP_HEADER = "x-qed-viewer-ip"
EDGE_SECRET_HEADER = "x-qed-edge"


def client_ip(request: Request) -> str:
    """The caller's IP as AWS saw it. The Lambda Web Adapter forwards the Function URL request context in
    `x-amzn-request-context`, and `http.sourceIp` there is set by AWS. X-Forwarded-For is NOT trusted, because the caller
    controls it and could rotate it to dodge the per-IP limit.

    Behind a CDN (e.g. CloudFront), `sourceIp` is the edge, not the caller. If `POAW_TRUSTED_EDGE_SECRET` is set, an
    `x-qed-viewer-ip` header is trusted ONLY when the request also carries `x-qed-edge` equal to that secret (the edge adds
    it; a direct caller can't know it), and the edge must overwrite any client-sent `x-qed-viewer-ip`."""
    import hmac
    import json
    import os
    edge_secret = os.environ.get("POAW_TRUSTED_EDGE_SECRET", "")
    if edge_secret:
        presented = request.headers.get(EDGE_SECRET_HEADER, "")
        viewer = request.headers.get(EDGE_IP_HEADER, "").strip()
        if viewer and presented and hmac.compare_digest(presented.encode(), edge_secret.encode()):
            return viewer[:64]
    ctx = request.headers.get("x-amzn-request-context")
    if ctx:
        try:
            ip = json.loads(ctx).get("http", {}).get("sourceIp")
            if ip:
                return str(ip)[:64]
        except (ValueError, AttributeError):
            pass
    return (request.client.host if request.client else "unknown")[:64]


class Credential(NamedTuple):
    """Who a bearer token speaks for. `scopes` is None for a workspace API key (full access to the key routes) and a set of
    scope names for a limited credential (e.g. an OAuth token); a route that needs a scope refuses a credential without it."""
    workspace_id: str
    scopes: frozenset[str] | None = None
    kind: str = "key"
    audience: str | None = None  # the resource server an OAuth token was issued for; None for an API key


def create_app(get_node: Callable[[], Awaitable[Node]], *, log_id: str, tick_enabled: Callable[[], bool],
               after_tick: Callable[[], Awaitable[dict]] | None = None,
               keyset: Callable[[], Awaitable[dict]] | None = None,
               admission: Callable[[str, ClaimIn], Awaitable[str | None]] | None = None,
               credential: Callable[[str], Awaitable[Credential | None]] | None = None) -> FastAPI:
    head_cache: dict[int, dict] = {}  # signed head per tree size, so a KMS signer isn't called on every read
    app = FastAPI(title="poaw-node", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(PublicCors)
    app.add_middleware(_BodyCap)  # inner to `harden`, so a 413 from either still gets the security headers

    @app.middleware("http")
    async def harden(request: Request, call_next):
        # SECURITY F3: cap the body before anything parses it.
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            from fastapi.responses import JSONResponse
            resp = JSONResponse({"detail": "request body too large"}, status_code=413)
        else:
            resp = await call_next(request)
        # SECURITY F7: headers on every response, and no caching of anything authenticated.
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        if request.headers.get("authorization"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.exception_handler(RequestValidationError)
    async def bad_params(request: Request, exc: RequestValidationError):
        # The public log API answers bad parameters with 400 (contract); every other route keeps FastAPI's 422.
        if request.url.path.startswith("/v1/log/"):
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "invalid query parameters"}, status_code=400)
        return await request_validation_exception_handler(request, exc)

    def limited() -> HTTPException:
        return HTTPException(status_code=429, detail="rate limit exceeded", headers={"Retry-After": "5"})

    async def node() -> Node:
        return await get_node()

    async def resolve(token: str, n: Node) -> Credential | None:
        # `credential` lets a deployment accept more than API keys (the hosted service accepts OAuth access tokens). Without
        # it a bearer token is a workspace API key, exactly as before.
        if credential is not None:
            return await credential(token)
        ws = await n.store.workspace_for_key(token)
        return Credential(ws) if ws else None

    def needs(scope: str | None):
        async def dep(authorization: str = Header(default=""), n: Node = Depends(node)) -> Credential:
            scheme, _, token = authorization.partition(" ")
            cred = await resolve(token, n) if scheme.lower() == "bearer" and token else None
            if not cred:
                raise HTTPException(status_code=401, detail="invalid or missing API key",
                                    headers={"WWW-Authenticate": "Bearer"})
            if scope and cred.scopes is not None and scope not in cred.scopes:
                raise HTTPException(status_code=403, detail=f"this credential lacks the {scope} scope")
            if not await n.store.rate_take(f"key:{key_hash(token)}", per_minute=CLAIMS_PER_MIN_PER_KEY):
                raise limited()
            return cred
        return dep

    async def _ws(cred: Credential = Depends(needs(None))) -> str:
        return cred.workspace_id

    def workspace_with(scope: str):
        async def dep(cred: Credential = Depends(needs(scope))) -> str:
            return cred.workspace_id
        return dep

    workspace = _ws  # any valid credential

    @app.get("/.well-known/poaw-keys.json")
    async def poaw_keys() -> dict:
        # SPEC §5.2 + §8.4: the receipt keys, and the anchor attesters and schemas a checker must accept. Public by design.
        if keyset is None:
            raise HTTPException(status_code=404)
        return await keyset()

    @app.get("/v1/whoami")
    async def whoami(cred: Credential = Depends(needs(None))) -> dict:
        # Lets a resource server (the hosted MCP) check a credential before using it. Any valid credential may ask.
        return {"workspace_id": cred.workspace_id, "kind": cred.kind,
                "scopes": sorted(cred.scopes) if cred.scopes is not None else None, "audience": cred.audience}

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True}

    @app.post("/v1/claims", status_code=202)
    async def submit(c: ClaimIn, ws: str = Depends(workspace_with("claims:submit")), n: Node = Depends(node)) -> dict:
        # A deployment's admission policy (e.g. a plan quota) may refuse a NEW claim up front. A refused claim creates
        # nothing and gets no receipt. Nothing here can change the verdict of a claim that was accepted.
        if admission is not None and (refusal := await admission(ws, c)):
            raise HTTPException(status_code=402, detail=refusal)
        try:
            claim, created = await n.submit(ws, c)
        except (ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=f"invalid params for {c.action}: {_brief(exc)}") from None
        receipt_id = None
        # First check inline, so fast destinations decide without waiting for the tick. Enclave-eligible claims skip it:
        # the enclave decides them, or the tick does once the window has passed.
        if created and not n.enclave_eligible(claim):
            attempts = await n.store.bump_attempt(claim.id)
            receipt_id = await n.check(claim, attempts=attempts)
        status = await n.store.claim_status(ws, claim.id)
        return {"claim_id": claim.id, "created": created, **(status or {}), "receipt_id": receipt_id or (status or {}).get("receipt_id")}

    @app.get("/v1/claims")
    async def list_claims(limit: int = Query(LIST_CLAIMS_DEFAULT_LIMIT, ge=1, le=LIST_CLAIMS_MAX_LIMIT),
                          cursor: str | None = None, agent_id: str | None = None, action: str | None = None,
                          verdict: str | None = None, state: str | None = None, ws: str = Depends(workspace_with("claims:read")),
                          n: Node = Depends(node)) -> dict:
        # Newest first, keyset-paginated on (created_at desc, id desc). `limit` items are returned; one extra row is
        # fetched to tell whether a next page exists, so `next_cursor` is only set when it does (SPEC parity: each
        # item is the exact dict shape claim_status returns).
        before = _decode_cursor(cursor) if cursor else None
        rows = await n.store.list_claims(ws, limit=limit + 1, before=before, agent_id=agent_id, action=action,
                                         verdict=verdict, state=state)
        more = len(rows) > limit
        rows = rows[:limit]
        claims = [{"claim_id": r["claim_id"], "state": r["state"], "attempts": r["attempts"],
                   "receipt_id": r["receipt_id"], "verdict": r["verdict"]} for r in rows]
        next_cursor = _encode_cursor(rows[-1]["created_at"], rows[-1]["claim_id"]) if more and rows else None
        return {"claims": claims, "next_cursor": next_cursor}

    @app.get("/v1/connections")
    async def list_connections(ws: str = Depends(workspace_with("claims:read")), n: Node = Depends(node)) -> dict:
        # What this workspace can have verified: each active connection with the verifier actions its provider
        # supports here, plus the actions that need no connection. Deliberately no account identifiers (the key holder
        # is usually an agent; the console shows names to signed-in members). Lane connections-list-api.
        load_builtin()
        by_provider: dict[str, list[str]] = {}
        public: list[str] = []
        for action, spec in REGISTRY.items():
            (by_provider.setdefault(spec.provider, []) if spec.provider else public).append(action)
        rows = await n.store.list_connections(ws)
        return {
            "connections": [{"id": r["id"], "provider": r["provider"], "scopes": sorted(r["scopes"] or []),
                             "connected_at": r["created_at"].isoformat().replace("+00:00", "Z"),
                             "actions": sorted(by_provider.get(r["provider"], []))} for r in rows],
            "public_actions": sorted(public),
        }

    @app.get("/v1/claims/{claim_id}")
    async def claim_status(claim_id: str, ws: str = Depends(workspace_with("claims:read")), n: Node = Depends(node)) -> dict:
        s = await n.store.claim_status(ws, claim_id)
        if not s:
            raise HTTPException(status_code=404, detail="claim not found")
        return s

    @app.get("/v1/receipts/{receipt_id}")
    async def receipt(receipt_id: str, request: Request, n: Node = Depends(node)) -> dict:
        # Receipts are designed to be shared and checked by anyone, so reading one needs no key (SPEC §1) — an
        # Authorization header is never required. But when one IS presented and resolves to a real workspace, the
        # read is rate-limited per KEY instead of per IP (many agents sharing an egress IP shouldn't share a budget).
        # An invalid/unknown key falls back to the IP bucket rather than failing the read. Deliberately a SEPARATE
        # bucket namespace (truncated hash) from the `key:<full hash>` bucket `workspace()` uses for writes, since
        # the two buckets carry different per-minute rates and rate_take's refill math assumes one rate per bucket.
        bucket = f"ip:{client_ip(request)}"
        scheme, _, key = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() == "bearer" and key and await n.store.workspace_for_key(key):
            bucket = f"key:{key_hash(key)[:16]}"
        if not await n.store.rate_take(bucket, per_minute=READS_PER_MIN_PER_IP):
            raise limited()
        r = await n.store.receipt_with_proof(receipt_id, log_id)
        if not r:
            raise HTTPException(status_code=404, detail="receipt not found")
        return r

    async def public_read(request: Request, n: Node) -> None:
        if not await n.store.rate_take(f"ip:{client_ip(request)}", per_minute=READS_PER_MIN_PER_IP):
            raise limited()

    @app.get("/v1/log/head")
    async def log_head(request: Request, n: Node = Depends(node)) -> dict:
        await public_read(request, n)
        size = await n.store.log_size()
        # An empty log is a valid, signed head: size 0 and the RFC 6962 root of the empty tree, SHA-256(""). A checker can
        # then tell "empty" from "unreachable", and the first receipt's head is consistent with it.
        root = poaw_core.sha256(b"") if size == 0 else await n.store.log_root(size)
        if root is None:
            raise HTTPException(status_code=503, detail="log root not available")
        cached = head_cache.get(size)
        if cached is None or cached["body"]["root_hash"] != poaw_core.b64u(root):
            body = poaw_core.tree_head_body(log_id, size, root, ts(datetime.now(timezone.utc)))
            sig = n.signer.sign(poaw_core.TREE_HEAD_SIG_DOMAIN + poaw_core.jcs(body))
            cached = {"body": body, "signature": {"alg": "Ed25519", "key_id": n.key_id, "value": poaw_core.b64u(sig)}}
            head_cache.clear()
            head_cache[size] = cached
        return {"tree_head": cached, "anchor": await n.store.latest_anchor()}

    @app.get("/v1/log/consistency")
    async def log_consistency(request: Request, first: int = Query(..., ge=1), second: int = Query(..., ge=1),
                              n: Node = Depends(node)) -> dict:
        await public_read(request, n)
        if first > second:
            raise HTTPException(status_code=400, detail="first must be <= second")
        if second > await n.store.log_size():
            raise HTTPException(status_code=404, detail="second is beyond the current tree size")
        first_root, second_root, proof = await n.store.log_consistency(first, second)
        return {"log_id": log_id, "first": first, "second": second, "first_root": poaw_core.b64u(first_root),
                "second_root": poaw_core.b64u(second_root), "proof": [poaw_core.b64u(h) for h in proof]}

    @app.get("/v1/log/proof")
    async def log_proof(request: Request, leaf_index: int = Query(..., ge=0), tree_size: int | None = Query(None, ge=1),
                        n: Node = Depends(node)) -> dict:
        await public_read(request, n)
        current = await n.store.log_size()
        size = current if tree_size is None else tree_size
        if size > current or leaf_index >= size:
            raise HTTPException(status_code=404, detail="no such leaf in a tree of that size")
        leaf, root, path = await n.store.log_inclusion(leaf_index, size)
        return {"log_id": log_id, "leaf_index": leaf_index, "tree_size": size, "leaf_hash": poaw_core.b64u(leaf),
                "root_hash": poaw_core.b64u(root), "inclusion": [poaw_core.b64u(h) for h in path]}

    @app.get("/v1/log/anchors")
    async def log_anchors(request: Request, limit: int = Query(ANCHORS_DEFAULT_LIMIT, ge=1, le=LOG_PAGE_MAX),
                          before: int | None = Query(None, ge=1), n: Node = Depends(node)) -> dict:
        await public_read(request, n)
        page, nxt = await n.store.list_anchors(limit, before)
        return {"anchors": page, "next": nxt}

    @app.get("/v1/log/entries")
    async def log_entries(request: Request, start: int | None = Query(None, ge=0),
                          limit: int = Query(ENTRIES_DEFAULT_LIMIT, ge=1, le=LOG_PAGE_MAX), n: Node = Depends(node)) -> dict:
        await public_read(request, n)
        size = await n.store.log_size()
        if start is None:
            start = max(0, size - ENTRIES_DEFAULT_LIMIT)
        elif start > size:
            raise HTTPException(status_code=404, detail="start is beyond the current tree size")
        entries = await n.store.list_entries(start, limit)
        nxt = start + len(entries)
        return {"tree_size": size, "entries": entries, "next": nxt if entries and nxt < size else None}

    @app.post("/events")
    async def events(request: Request, n: Node = Depends(node)) -> dict:
        if not tick_enabled():
            raise HTTPException(status_code=404)
        result = await n.tick()
        if after_tick is not None:  # e.g. the anchorer. It runs after claims are decided, so the anchored root includes them
            result.update(await after_tick())
        return result

    return app


def _brief(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        return "; ".join(f"{'.'.join(map(str, e['loc'])) or 'params'}: {e['msg']}" for e in exc.errors()[:5])
    return str(exc)[:200]
