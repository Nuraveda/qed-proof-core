"""Audit fixes #233 #234 #238 #239: a verifier that cannot see the whole truth must say so, never VERIFIED."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import respx

from poaw_node.models import Claim, Observed, Reason, Retry, Unverifiable, Verdict
from poaw_node.verifiers import github, http as httpv

T0 = datetime(2026, 9, 25, 14, 0, tzinfo=timezone.utc)
SHA = "a" * 40
REPO = f"{github.API}/repos/octo/repo"


class _Tok:
    def token(self):
        return "t"


def _claim(action="github.commit.push", target="octo/repo", params=None) -> Claim:
    return Claim(id="c1", workspace_id="w1", agent_ref="agent-1", client_claim_id="cc-1", action=action, target=target,
                 params=params or {}, claimed_at=T0, deadline_at=T0 + timedelta(minutes=15))


# -- #233: branch is a path component, never a URL fragment/query ------------------------------------------------------
@respx.mock
async def test_branch_with_fragment_never_reaches_the_compare_endpoint():
    _suites()
    respx.get(f"{REPO}/commits/{SHA}").respond(200, json={"commit": {"committer": {"date": "2026-09-25T14:00:00Z"}}})
    compare = respx.get(url__startswith=f"{REPO}/compare/").respond(200, json={"status": "identical"})
    async with httpx.AsyncClient() as c:
        r = await github.commit_push(_claim(params={"sha": SHA, "branch": "main#missing"}), _Tok(), c)
    assert not compare.called, "`main#missing` must not be sent as a request for `main`"
    assert isinstance(r, Unverifiable) and r.reason is Reason.CLAIM_AMBIGUOUS


@respx.mock
async def test_branch_names_that_git_refuses_are_ambiguous_without_a_request():
    commits = respx.get(url__startswith=f"{REPO}/").respond(200, json={"status": "identical"})
    for bad in ("a..b", "a b", "-x", "/x", "x/", "x.lock", "x.", "a@{b", "a//b", "a?b", "a%2Fb", "a~b", "a^b", "a:b",
                "a*b", "a[b", "a\\b", "a\x01b", "@", "a/.b", "a.lock/b"):
        async with httpx.AsyncClient() as c:
            r = await github.commit_push(_claim(params={"sha": SHA, "branch": bad}), _Tok(), c)
        assert isinstance(r, Unverifiable) and r.reason is Reason.CLAIM_AMBIGUOUS, bad
    assert not commits.called


@respx.mock
async def test_slashed_branch_is_requested_as_a_path():
    respx.get(f"{REPO}/commits/{SHA}").respond(200, json={"commit": {"committer": {"date": "2026-09-25T14:00:00Z"}}})
    compare = respx.get(f"{REPO}/compare/{SHA}...feature/x-1").respond(200, json={"status": "ahead"})
    async with httpx.AsyncClient() as c:
        r = await github.commit_push(_claim(params={"sha": SHA, "branch": "feature/x-1"}), _Tok(), c)
    assert compare.called and isinstance(r, Observed) and r.outcome is Verdict.VERIFIED


# -- #234: never fingerprint a body prefix ---------------------------------------------------------------------------
async def _pin(monkeypatch):
    async def fake_resolve(host):
        return "93.184.216.34"
    monkeypatch.setattr(httpv, "resolve_public", fake_resolve)


def _url_claim(fp):
    return _claim("http.url.status", "https://status.example.com/p", {"status": 200, "content_fingerprint": fp})


@respx.mock
async def test_oversized_body_is_never_verified_from_a_prefix(monkeypatch):
    await _pin(monkeypatch)
    prefix = "a" * httpv.MAX_BODY
    respx.get("https://93.184.216.34/p").respond(200, content=(prefix + "tail the agent changed").encode())
    async with httpx.AsyncClient() as c:
        r = await httpv.url_status(_url_claim(httpv.fingerprint(prefix)), None, c)
    assert isinstance(r, Unverifiable), r


@respx.mock
async def test_body_within_the_cap_still_verifies_with_the_full_fingerprint(monkeypatch):
    await _pin(monkeypatch)
    body = "a" * httpv.MAX_BODY
    respx.get("https://93.184.216.34/p").respond(200, content=body.encode())
    async with httpx.AsyncClient() as c:
        r = await httpv.url_status(_url_claim(httpv.fingerprint(body)), None, c)
    assert isinstance(r, Observed) and r.outcome is Verdict.VERIFIED
    assert r.facts["content_fingerprint"] == httpv.fingerprint(body)


# -- #238: every check run counts -------------------------------------------------------------------------------------
def _suites(total=1, status=200):
    respx.get(f"{REPO}/commits/{SHA}/check-suites").respond(status, json={"total_count": total, "check_suites": []})


def _runs(n, failing_last=False):
    runs = [{"name": f"job{i}", "status": "completed", "conclusion": "success"} for i in range(n)]
    if failing_last:
        runs[-1]["conclusion"] = "failure"
    return runs


@respx.mock
async def test_a_failing_101st_check_run_is_seen():
    _suites()
    runs = _runs(101, failing_last=True)
    base = f"{REPO}/commits/{SHA}/check-runs"
    respx.get(base, params={"per_page": "100", "page": "1"}).respond(200, json={"total_count": 101, "check_runs": runs[:100]})
    respx.get(base, params={"per_page": "100", "page": "2"}).respond(200, json={"total_count": 101, "check_runs": runs[100:]})
    async with httpx.AsyncClient() as c:
        r = await github.checks_pass(_claim("github.checks.pass", params={"sha": SHA}), _Tok(), c)
    assert isinstance(r, Observed) and r.outcome is Verdict.MISMATCH
    assert r.facts["check_runs"] == 101 and r.facts["failing"] == ["job100"]


@respx.mock
async def test_check_runs_that_cannot_be_fully_listed_are_not_verified():
    _suites()
    base = f"{REPO}/commits/{SHA}/check-runs"
    respx.get(base, params={"per_page": "100", "page": "1"}).respond(200, json={"total_count": 101, "check_runs": _runs(100)})
    respx.get(base, params={"per_page": "100", "page": "2"}).respond(502)
    async with httpx.AsyncClient() as c:
        r = await github.checks_pass(_claim("github.checks.pass", params={"sha": SHA}), _Tok(), c)
    assert isinstance(r, Retry)


@respx.mock
async def test_all_check_runs_green_across_pages_verifies_with_full_count():
    _suites()
    runs = _runs(150)
    base = f"{REPO}/commits/{SHA}/check-runs"
    respx.get(base, params={"per_page": "100", "page": "1"}).respond(200, json={"total_count": 150, "check_runs": runs[:100]})
    respx.get(base, params={"per_page": "100", "page": "2"}).respond(200, json={"total_count": 150, "check_runs": runs[100:]})
    async with httpx.AsyncClient() as c:
        r = await github.checks_pass(_claim("github.checks.pass", params={"sha": SHA}), _Tok(), c)
    assert isinstance(r, Observed) and r.outcome is Verdict.VERIFIED and r.facts["check_runs"] == 150


@respx.mock
async def test_more_check_runs_than_the_bound_is_never_verified():
    _suites()
    base = f"{REPO}/commits/{SHA}/check-runs"
    respx.get(url__startswith=base).respond(200, json={"total_count": 5000, "check_runs": _runs(100)})
    async with httpx.AsyncClient() as c:
        r = await github.checks_pass(_claim("github.checks.pass", params={"sha": SHA}), _Tok(), c)
    assert isinstance(r, Unverifiable)


# -- #239: a 404 on a PR is only "no such PR" when the repo is readable -----------------------------------------------
@respx.mock
async def test_pr_404_on_an_unreadable_repo_is_unverifiable():
    respx.get(f"{REPO}/pulls/7").respond(404)
    respx.get(REPO).respond(404)
    async with httpx.AsyncClient() as c:
        r = await github.pr_open(_claim("github.pr.open", params={"number": 7}), _Tok(), c)
    assert isinstance(r, Unverifiable) and r.reason is Reason.PERMISSION_DENIED
    async with httpx.AsyncClient() as c:
        r = await github.pr_open(_claim("github.pr.open", params={"number": 7}), None, c)
    assert isinstance(r, Unverifiable) and r.reason is Reason.NO_CONNECTION


@respx.mock
async def test_pr_404_on_a_readable_repo_is_still_failed():
    respx.get(f"{REPO}/pulls/7").respond(404)
    respx.get(REPO).respond(200, json={})
    async with httpx.AsyncClient() as c:
        r = await github.pr_open(_claim("github.pr.open", params={"number": 7}), _Tok(), c)
    assert isinstance(r, Observed) and r.outcome is Verdict.FAILED


# -- round 2 #234: the cap applies to bytes on the wire, never to decompressed chunks ---------------------------------
class _Counting(httpx.AsyncByteStream):
    def __init__(self, chunk: bytes, n: int):
        self.chunk, self.n, self.sent = chunk, n, 0

    async def __aiter__(self):
        for _ in range(self.n):
            self.sent += len(self.chunk)
            yield self.chunk


async def _stream_run(monkeypatch, headers, stream, fp="sha256:x"):
    await _pin(monkeypatch)
    seen = {}

    def handler(request):
        seen["accept_encoding"] = request.headers.get("accept-encoding")
        return httpx.Response(200, headers=headers, stream=stream)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        return await httpv.url_status(_url_claim(fp), None, c), seen


async def test_compressed_body_is_refused_unread(monkeypatch):
    import gzip
    bomb = gzip.compress(b"a" * 8_000_000)
    stream = _Counting(bomb, 1)
    r, seen = await _stream_run(monkeypatch, {"content-encoding": "gzip"}, stream)
    assert seen["accept_encoding"] == "identity"
    assert isinstance(r, Unverifiable) and r.reason is Reason.DESTINATION_UNAVAILABLE
    assert stream.sent == 0, "a compressed body must not be read at all"


async def test_identity_body_read_stops_shortly_after_the_cap(monkeypatch):
    stream = _Counting(b"a" * 1000, 100_000)  # 100 MB offered
    r, _ = await _stream_run(monkeypatch, {}, stream)
    assert isinstance(r, Unverifiable) and r.reason is Reason.DESTINATION_UNAVAILABLE
    assert stream.sent <= httpv.MAX_BODY + 200_000


# -- round 2 #238: all runs, and the endpoint's own 1000-suite ceiling ------------------------------------------------
@respx.mock
async def test_check_runs_request_filter_latest():
    _suites()
    base = f"{REPO}/commits/{SHA}/check-runs"
    route = respx.get(url__startswith=base).respond(200, json={"total_count": 1, "check_runs": _runs(1)})
    async with httpx.AsyncClient() as c:
        await github.checks_pass(_claim("github.checks.pass", params={"sha": SHA}), _Tok(), c)
    assert route.calls.last.request.url.params["filter"] == "latest"


@respx.mock
async def test_total_count_at_the_endpoint_ceiling_is_not_verified():
    _suites()
    base = f"{REPO}/commits/{SHA}/check-runs"
    respx.get(url__startswith=base).respond(200, json={"total_count": 1000, "check_runs": _runs(100)})
    async with httpx.AsyncClient() as c:
        r = await github.checks_pass(_claim("github.checks.pass", params={"sha": SHA}), _Tok(), c)
    assert isinstance(r, Unverifiable)


@respx.mock
async def test_failed_run_superseded_by_a_green_rerun_verifies():
    _suites()
    base = f"{REPO}/commits/{SHA}/check-runs"
    respx.get(url__startswith=base).respond(200, json={"total_count": 1, "check_runs": _runs(1)})  # latest only: the green re-run
    async with httpx.AsyncClient() as c:
        r = await github.checks_pass(_claim("github.checks.pass", params={"sha": SHA}), _Tok(), c)
    assert isinstance(r, Observed) and r.outcome is Verdict.VERIFIED


@respx.mock
async def test_suite_count_over_the_ceiling_is_not_verified_even_if_one_run_is_listed():
    _suites(1001)
    base = f"{REPO}/commits/{SHA}/check-runs"
    respx.get(url__startswith=base).respond(200, json={"total_count": 1, "check_runs": _runs(1)})
    async with httpx.AsyncClient() as c:
        r = await github.checks_pass(_claim("github.checks.pass", params={"sha": SHA}), _Tok(), c)
    assert isinstance(r, Unverifiable) and r.reason is Reason.DESTINATION_UNAVAILABLE


@respx.mock
async def test_check_suites_call_failing_is_retry():
    _suites(status=502)
    async with httpx.AsyncClient() as c:
        r = await github.checks_pass(_claim("github.checks.pass", params={"sha": SHA}), _Tok(), c)
    assert isinstance(r, Retry)


@respx.mock
async def test_check_suites_without_an_integer_total_is_not_verified():
    _suites()
    respx.get(f"{REPO}/commits/{SHA}/check-suites").respond(200, json={"check_suites": []})
    async with httpx.AsyncClient() as c:
        r = await github.checks_pass(_claim("github.checks.pass", params={"sha": SHA}), _Tok(), c)
    assert isinstance(r, Unverifiable)
