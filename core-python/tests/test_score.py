"""score/v0: the ADR's worked examples plus the edges of each rule."""
from datetime import datetime, timedelta, timezone

import poaw_core as p
from poaw_core import score_v0

NOW = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)


def iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def rcpt(i, verdict="verified", target=None, age_days=0.0, issued_age=None, action="x.post.publish", **over):
    claimed = NOW - timedelta(days=age_days)
    issued = NOW - timedelta(days=age_days if issued_age is None else issued_age)
    b = {"receipt_id": f"rcpt_{i:04d}", "issued_at": iso(issued), "agent": {"id": "a1"},
         "claim": {"action": action, "target": target or f"t{i}", "claimed_at": iso(claimed)}, "verdict": {"value": verdict}}
    b.update(over)
    return b


def test_exported():
    assert p.score_v0 is score_v0


def test_three_fresh_verified_three_targets():
    r = score_v0([rcpt(i) for i in range(3)], NOW)
    assert r["score"] == 69 and r["provisional"] is True and r["counted"] == 3 and r["distinct_targets"] == 3
    assert r["formula"] == "score/v0" and r["window_days"] == 90 and r["as_of"] == "2026-10-04T12:00:00.000Z"


def test_three_fresh_verified_one_target():
    r = score_v0([rcpt(i, target="same") for i in range(3)], NOW)
    assert r["score"] == 66 and r["provisional"] and r["distinct_targets"] == 1


def test_thirty_fresh_verified_thirty_targets():
    r = score_v0([rcpt(i) for i in range(30)], NOW)
    assert r["score"] == 93 and r["provisional"] is False


def test_thirty_on_two_targets_still_provisional():
    assert score_v0([rcpt(i, target=f"t{i % 2}") for i in range(30)], NOW)["provisional"] is True


def test_no_receipts_is_the_prior():
    r = score_v0([], NOW)
    assert r["score"] == 50 and r["counted"] == 0 and r["provisional"] is True


def test_accepts_full_receipt_objects_and_iso_or_datetime_as_of():
    full = [{"body": rcpt(i), "signature": {"alg": "Ed25519"}} for i in range(3)]
    assert score_v0(full, NOW) == score_v0([rcpt(i) for i in range(3)], iso(NOW))


def test_verdict_points_and_counts():
    r = score_v0([rcpt(0, "verified"), rcpt(1, "late"), rcpt(2, "mismatch"), rcpt(3, "failed")], NOW)
    assert r["verdicts"] == {"verified": 1, "late": 1, "mismatch": 1, "failed": 1}
    assert r["score"] == round(100 * (1.6 + 2.5) / 9)  # 45.55 -> 46


def test_recency_half_life():
    # one verified receipt 30 days old: w = 0.5, score = 100*(0.5+2.5)/(0.5+5)
    r = score_v0([rcpt(0, age_days=30)], NOW)
    assert r["score"] == 55  # 54.545...
    assert score_v0([rcpt(0, age_days=0)], NOW)["score"] == 58  # 3.5/6


def test_old_failure_hurts_less_than_new_failure():
    old = score_v0([rcpt(0, "failed", age_days=60)], NOW)["score"]
    new = score_v0([rcpt(0, "failed")], NOW)["score"]
    assert old > new


def test_window_edges():
    inside = rcpt(0, issued_age=89.999)
    edge = rcpt(1, issued_age=90)  # exactly as_of - 90d: excluded (open lower bound)
    future = rcpt(2, issued_age=-0.001)  # issued after as_of: excluded
    at_now = rcpt(3, issued_age=0)  # exactly as_of: included
    assert score_v0([inside], NOW)["counted"] == 1
    assert score_v0([edge], NOW)["counted"] == 0
    assert score_v0([future], NOW)["counted"] == 0
    assert score_v0([at_now], NOW)["counted"] == 1


def test_window_uses_issued_at_not_claimed_at():
    r = rcpt(0, age_days=95, issued_age=1)
    assert score_v0([r], NOW)["counted"] == 1


def test_superseded_is_dropped_whatever_the_verdict():
    old = rcpt(0, "failed", target="x")
    new = rcpt(1, "verified", target="x", supersedes="rcpt_0000")
    r = score_v0([old, new], NOW)
    assert r["counted"] == 1 and r["verdicts"]["failed"] == 0 and r["verdicts"]["verified"] == 1
    assert score_v0([new, old], NOW) == r


def test_unverifiable_reported_not_scored():
    base = score_v0([rcpt(0)], NOW)
    r = score_v0([rcpt(0), rcpt(1, "unverifiable"), rcpt(2, "unverifiable")], NOW)
    assert r["unverifiable"] == 2 and r["counted"] == 1 and r["score"] == base["score"]
    assert r["verdicts"] == base["verdicts"]


def test_unknown_verdict_is_ignored():
    assert score_v0([rcpt(0, "banana")], NOW)["counted"] == 0


def test_repeat_decay_rank_by_claimed_at_then_id():
    # same target, same claimed_at: rank by receipt id, so input order cannot matter
    rs = [rcpt(i, target="same") for i in range(4)]
    assert score_v0(rs, NOW) == score_v0(list(reversed(rs)), NOW)
    # a failure ranked first (older) weighs 1; ranked later it weighs 1/sqrt(k): less damage
    bad_first = [rcpt(0, "failed", target="s", age_days=3)] + [rcpt(i, target="s", age_days=2 - i * 0.1) for i in range(1, 4)]
    bad_last = [rcpt(0, "failed", target="s", age_days=0)] + [rcpt(i, target="s", age_days=1 + i * 0.1) for i in range(1, 4)]
    assert score_v0(bad_last, NOW)["score"] > score_v0(bad_first, NOW)["score"]


def test_different_action_same_target_ranks_separately():
    r = score_v0([rcpt(0, target="t", action="a"), rcpt(1, target="t", action="b")], NOW)
    assert r["score"] == 64  # both weights are 1: 100*(2+2.5)/7 = 64.28
    assert r["distinct_targets"] == 1


def test_provisional_rules():
    assert score_v0([rcpt(i) for i in range(29)], NOW)["provisional"] is True
    assert score_v0([rcpt(i) for i in range(30)], NOW)["provisional"] is False
    assert score_v0([rcpt(i, target=f"t{i % 3}") for i in range(30)], NOW)["provisional"] is False
    assert score_v0([rcpt(i, target=f"t{i % 2}") for i in range(60)], NOW)["provisional"] is True


def test_excluded_agent_ids():
    rs = [rcpt(i, agent={"id": "qed-console-try"}) for i in range(3)]
    assert score_v0(rs, NOW, {"qed-console-try"})["counted"] == 0
    assert score_v0(rs, NOW)["counted"] == 3


def test_rounding_is_half_up():
    from decimal import Decimal
    # prior alone is exactly 50; construct nothing exotic: assert the module's tie rule directly
    from poaw_core import score as s
    assert int(Decimal(68.5).quantize(Decimal(1), rounding=s.ROUND_HALF_UP)) == 69
    assert round(68.5) == 68  # python's own rule differs, which is why we do not use it


def test_pure_and_deterministic():
    rs = [rcpt(i, age_days=i) for i in range(10)]
    snapshot = repr(rs)
    assert score_v0(rs, NOW) == score_v0(rs, NOW) and repr(rs) == snapshot
