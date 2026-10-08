"""http.url.status v1. HTTPS only, with an SSRF guard (no private, loopback or link-local destinations)."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
import poaw_core

from ..models import Claim, Observed, Reason, Retry, Unverifiable, Verdict
from . import Params, VerifierSpec, register


class UrlParams(Params):
    status: int = 200
    content_fingerprint: str | None = None

MAX_BODY = 1_000_000


def normalise(text: str) -> bytes:
    """SPEC §4.4 fingerprint normalisation: NFC, LF endings, strip trailing whitespace per line and blank edges."""
    import unicodedata
    lines = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).strip("\n").encode("utf-8")


def fingerprint(text: str) -> str:
    return "sha256:" + poaw_core.b64u(poaw_core.sha256(normalise(text)))


async def resolve_public(host: str) -> str | None:
    """Resolve once. Return ONE address to connect to, and only if EVERY resolved address is global. Otherwise None.
    The caller connects to exactly this address (SECURITY F4: no second resolution, so no DNS-rebinding window)."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        return None
    addrs = [info[4][0] for info in infos]
    if not addrs or not all(ipaddress.ip_address(a).is_global for a in addrs):
        return None
    v4 = [a for a in addrs if ipaddress.ip_address(a).version == 4]  # non-VPC Lambda has no IPv6 egress
    return v4[0] if v4 else None


def pinned_url(parts, ip: str) -> str:
    host = f"[{ip}]" if ":" in ip else ip
    netloc = host if parts.port in (None, 443) else f"{host}:{parts.port}"
    return parts._replace(netloc=netloc).geturl()


async def url_status(claim: Claim, creds, client: httpx.AsyncClient):
    parts = urlsplit(claim.target)
    want = claim.params.get("status", 200)
    want_fp = claim.params.get("content_fingerprint")
    if parts.scheme != "https" or not parts.hostname or not isinstance(want, int):
        return Unverifiable(Reason.CLAIM_AMBIGUOUS, "target must be an https URL and params.status an integer")
    ip = await resolve_public(parts.hostname)
    if ip is None:
        return Unverifiable(Reason.PERMISSION_DENIED, "destination is not a public address")
    try:
        # Connect to the validated IP. Host + SNI stay the original name, so TLS still verifies the certificate
        # against the name. Redirects aren't followed: one could lead to a non-public host.
        async with client.stream("GET", pinned_url(parts, ip), timeout=10, follow_redirects=False,
                                 headers={"User-Agent": "poaw-node-http-verifier", "Host": parts.netloc,
                                          "Accept-Encoding": "identity"},
                                 extensions={"sni_hostname": parts.hostname}) as resp:
            body = b""
            if want_fp is not None and resp.status_code == want:  # only fingerprint what we'd compare; hard byte cap
                # Raw wire bytes only: a decoded chunk can be arbitrarily larger than what was sent (compression bomb).
                if resp.headers.get("content-encoding", "identity").strip().lower() not in ("", "identity"):
                    return Unverifiable(Reason.DESTINATION_UNAVAILABLE, "compressed body refused despite Accept-Encoding: identity")
                async for chunk in resp.aiter_raw(chunk_size=65536):
                    body += chunk
                    if len(body) > MAX_BODY:
                        return Unverifiable(Reason.DESTINATION_UNAVAILABLE, f"body larger than {MAX_BODY} bytes cannot be fingerprinted")
            encoding = resp.encoding
    except httpx.HTTPError as exc:
        return Retry(Reason.DESTINATION_UNAVAILABLE, type(exc).__name__)
    facts = {"url": claim.target, "status": resp.status_code}
    now = datetime.now(timezone.utc)
    if resp.status_code != want:
        if resp.status_code >= 500 or resp.status_code == 429:
            return Retry(Reason.RATE_LIMITED if resp.status_code == 429 else Reason.DESTINATION_UNAVAILABLE,
                         f"HTTP {resp.status_code}")
        return Observed(facts, Verdict.FAILED if resp.status_code == 404 else Verdict.MISMATCH,
                        Reason.NOT_FOUND if resp.status_code == 404 else Reason.CONTENT_MISMATCH, observed_at=now,
                        final=resp.status_code != 404)
    if want_fp is not None:
        got = fingerprint(body.decode(encoding or "utf-8", errors="replace"))
        facts["content_fingerprint"] = got
        if got != want_fp:
            return Observed(facts, Verdict.MISMATCH, Reason.CONTENT_MISMATCH, observed_at=now)
    return Observed(facts, Verdict.VERIFIED, observed_at=now)


register(VerifierSpec("http.url.status", "1", None, timedelta(minutes=5), timedelta(minutes=10), url_status, UrlParams))
