"""github.* verifiers v1 (SPEC §9). Read-only GitHub REST calls. Facts carry IDs and states, never file contents."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import httpx
import poaw_core

from ..models import Claim, Observed, Reason, Retry, Unverifiable, Verdict
from . import Params, VerifierSpec, register


MAX_FAILING_NAMES, MAX_FAILING_NAME, MAX_FAILING_BYTES = 10, 64, 700  # names, bytes per name (UTF-8), bytes of the whole JSON list


class PushParams(Params):
    sha: str
    branch: str


class PrParams(Params):
    number: int
    base: str | None = None
    head_sha: str | None = None


class ChecksParams(Params):
    sha: str

API = "https://api.github.com"
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_BAD_BRANCH_CHARS = re.compile(r"[\x00-\x20\x7f~^:?*\[\\#%]")
CHECK_PAGES_MAX = 10  # 1000 runs; a commit with more than this can't be fully enumerated, so it is never VERIFIED
CHECK_RUNS_CEILING = 1000  # the endpoint only covers the newest 1000 check suites (and 1000 runs here): at or above this, we cannot see everything


def _valid_branch(b: str) -> bool:
    """git check-ref-format --branch rules, plus `#`, `%` and `?` (they'd change which URL we actually request)."""
    return not (not b or b == "@" or b.startswith(("-", "/")) or b.endswith(("/", ".")) or ".." in b or "//" in b
                or "@{" in b or _BAD_BRANCH_CHARS.search(b)
                or any(p.startswith(".") or p.endswith(".lock") for p in b.split("/")))


def _headers(creds) -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "poaw-node"}
    tok = creds.token() if creds else None
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _transport_reason(resp: httpx.Response) -> Reason:
    if resp.status_code == 429 or (resp.status_code == 403 and resp.headers.get("x-ratelimit-remaining") == "0"):
        return Reason.RATE_LIMITED
    if resp.status_code in (401, 403):
        return Reason.PERMISSION_DENIED
    return Reason.DESTINATION_UNAVAILABLE


async def _get(client: httpx.AsyncClient, url: str, creds) -> httpx.Response | Retry:
    try:
        return await client.get(url, headers=_headers(creds), timeout=10)
    except httpx.HTTPError as exc:
        return Retry(Reason.DESTINATION_UNAVAILABLE, type(exc).__name__)


def _parse_time(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def commit_push(claim: Claim, creds, client: httpx.AsyncClient):
    """Verified iff `branch` contains `sha` on the remote. Absent SHA → failed (retried until the deadline)."""
    sha, branch = claim.params.get("sha"), claim.params.get("branch")
    if not _REPO.match(claim.target) or not isinstance(sha, str) or not _SHA.match(sha) or not isinstance(branch, str) or not _valid_branch(branch):
        return Unverifiable(Reason.CLAIM_AMBIGUOUS, "need target owner/repo, params.sha (40 hex), params.branch (a valid branch name)")

    r = await _get(client, f"{API}/repos/{claim.target}/commits/{sha}", creds)
    if isinstance(r, Retry):
        return r
    if r.status_code == 404:
        # 404 is also what GitHub returns for a private repo without access, so only a readable repo can blame the agent.
        repo = await _get(client, f"{API}/repos/{claim.target}", creds)
        if isinstance(repo, Retry):
            return repo
        if repo.status_code != 200:
            return Unverifiable(Reason.NO_CONNECTION if not (creds and creds.token()) else Reason.PERMISSION_DENIED,
                                "repository not readable")
        return Observed({"sha": sha, "branch": branch, "commit_found": False}, Verdict.FAILED, Reason.NOT_FOUND,
                        observed_at=_now(), final=False)
    if r.status_code in (422,):
        return Observed({"sha": sha, "branch": branch, "commit_found": False}, Verdict.FAILED, Reason.NOT_FOUND,
                        observed_at=_now(), final=False)
    if r.status_code != 200:
        return Retry(_transport_reason(r), f"commit HTTP {r.status_code}")
    committed_at = _parse_time(r.json().get("commit", {}).get("committer", {}).get("date"))

    c = await _get(client, f"{API}/repos/{claim.target}/compare/{sha}...{quote(branch, safe='/')}", creds)
    if isinstance(c, Retry):
        return c
    if c.status_code == 404:
        return Observed({"sha": sha, "branch": branch, "commit_found": True, "branch_found": False},
                        Verdict.MISMATCH, Reason.TARGET_MISMATCH, observed_at=_now(), final=False)
    if c.status_code != 200:
        return Retry(_transport_reason(c), f"compare HTTP {c.status_code}")
    status = c.json().get("status")  # identical | ahead | behind | diverged, from sha's point of view to branch
    on_branch = status in ("identical", "ahead")
    facts = {"sha": sha, "branch": branch, "commit_found": True, "branch_contains_sha": on_branch}
    if on_branch:
        return Observed(facts, Verdict.VERIFIED, observed_at=_now(), appeared_at=None, final=True)
    return Observed(facts, Verdict.MISMATCH, Reason.TARGET_MISMATCH, observed_at=_now(), final=False)


async def pr_open(claim: Claim, creds, client: httpx.AsyncClient):
    number, base, head_sha = claim.params.get("number"), claim.params.get("base"), claim.params.get("head_sha")
    if not _REPO.match(claim.target) or not isinstance(number, int) or number < 1:
        return Unverifiable(Reason.CLAIM_AMBIGUOUS, "need target owner/repo and integer params.number")
    r = await _get(client, f"{API}/repos/{claim.target}/pulls/{number}", creds)
    if isinstance(r, Retry):
        return r
    if r.status_code == 404:
        # Same as commit_push: 404 is also what a private repo without access returns.
        repo = await _get(client, f"{API}/repos/{claim.target}", creds)
        if isinstance(repo, Retry):
            return repo
        if repo.status_code != 200:
            return Unverifiable(Reason.NO_CONNECTION if not (creds and creds.token()) else Reason.PERMISSION_DENIED,
                                "repository not readable")
        return Observed({"number": number, "pr_found": False}, Verdict.FAILED, Reason.NOT_FOUND, observed_at=_now(), final=False)
    if r.status_code != 200:
        return Retry(_transport_reason(r), f"pull HTTP {r.status_code}")
    pr = r.json()
    facts = {"number": number, "pr_found": True, "state": pr.get("state"), "base": pr.get("base", {}).get("ref"),
             "head_sha": pr.get("head", {}).get("sha")}
    if base is not None and facts["base"] != base:
        return Observed(facts, Verdict.MISMATCH, Reason.TARGET_MISMATCH, observed_at=_now())
    if head_sha is not None and facts["head_sha"] != head_sha:
        return Observed(facts, Verdict.MISMATCH, Reason.CONTENT_MISMATCH, observed_at=_now())
    return Observed(facts, Verdict.VERIFIED, observed_at=_now(), appeared_at=_parse_time(pr.get("created_at")))


async def checks_pass(claim: Claim, creds, client: httpx.AsyncClient):
    sha = claim.params.get("sha")
    if not _REPO.match(claim.target) or not isinstance(sha, str) or not _SHA.match(sha):
        return Unverifiable(Reason.CLAIM_AMBIGUOUS, "need target owner/repo and params.sha (40 hex)")
    # The runs endpoint only covers the newest 1000 check SUITES, but its total_count counts runs. Check the suite count first.
    su = await _get(client, f"{API}/repos/{claim.target}/commits/{sha}/check-suites?per_page=1", creds)
    if isinstance(su, Retry):
        return su
    if su.status_code != 200:
        return Retry(_transport_reason(su), f"check-suites HTTP {su.status_code}")
    suites = su.json().get("total_count")
    if not isinstance(suites, int) or isinstance(suites, bool) or suites >= CHECK_RUNS_CEILING:
        return Unverifiable(Reason.DESTINATION_UNAVAILABLE, f"{suites} check suites exceeds what can be enumerated")
    runs: list = []
    for page in range(1, CHECK_PAGES_MAX + 1):
        r = await _get(client, f"{API}/repos/{claim.target}/commits/{sha}/check-runs?filter=latest&per_page=100&page={page}", creds)
        if isinstance(r, Retry):
            return r
        if r.status_code != 200:
            return Retry(_transport_reason(r), f"check-runs HTTP {r.status_code}")
        body = r.json()
        batch = body.get("check_runs", [])
        total = body.get("total_count", len(batch))
        if total >= CHECK_RUNS_CEILING:
            return Unverifiable(Reason.DESTINATION_UNAVAILABLE, f"{total} check runs exceeds what the endpoint can enumerate")
        runs += batch
        if len(runs) >= total or not batch:
            break
    if len(runs) < total:
        return Unverifiable(Reason.DESTINATION_UNAVAILABLE, f"could not enumerate all {total} check runs")
    if not runs:
        return Observed({"sha": sha, "check_runs": 0}, Verdict.FAILED, Reason.NOT_FOUND, observed_at=_now(), final=False)
    if any(run.get("status") != "completed" for run in runs):
        return Retry(Reason.DESTINATION_UNAVAILABLE, "checks still running")
    ok = {"success", "neutral", "skipped"}
    failing = sorted(run.get("name", "?") for run in runs if run.get("conclusion") not in ok)
    # Destination-derived, so bounded here by ENCODED size (receipts must fit the signer's 4096 bytes): the first names, each
    # cut to MAX_FAILING_NAME UTF-8 bytes, trailing names dropped to fit MAX_FAILING_BYTES of canonical JSON, and the full count.
    names = [str(n).encode()[:MAX_FAILING_NAME].decode(errors="ignore") for n in failing[:MAX_FAILING_NAMES]]
    while names and len(poaw_core.jcs(names)) > MAX_FAILING_BYTES:  # canonical JSON bytes, escapes included
        names.pop()
    facts = {"sha": sha, "check_runs": len(runs), "failing": names, "failing_total": len(failing)}
    if failing:
        return Observed(facts, Verdict.MISMATCH, Reason.CONTENT_MISMATCH, observed_at=_now())
    return Observed(facts, Verdict.VERIFIED, observed_at=_now())


register(VerifierSpec("github.commit.push", "1", "github", timedelta(minutes=10), timedelta(minutes=15), commit_push, PushParams))
register(VerifierSpec("github.pr.open", "1", "github", timedelta(minutes=10), timedelta(minutes=15), pr_open, PrParams))
register(VerifierSpec("github.checks.pass", "1", "github", timedelta(hours=1), timedelta(hours=2), checks_pass, ChecksParams))
