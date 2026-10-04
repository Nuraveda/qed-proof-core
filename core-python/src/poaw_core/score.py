"""score/v0: the provisional reputation score, a deterministic function of one agent's receipts (SPEC appendix).

No model and no hidden inputs: anyone holding the receipts and an `as_of` gets the same number.

Rounding: the final `100 * (sum(w*s) + K*P) / (sum(w) + K)` is rounded HALF UP (a .5 goes to the next integer), done with
`decimal` on the exact binary value of the float result. It is NOT Python's `round()` (half to even), so other
implementations can reproduce it with any round-half-up. Exact .5 ties are vanishingly rare with these weights.
"""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Iterable

FORMULA = "score/v0"
WINDOW_DAYS = 90
HALF_LIFE_DAYS = 30
PRIOR_K = 5
PRIOR_P = 0.5
PROVISIONAL_MIN_COUNTED = 30
PROVISIONAL_MIN_TARGETS = 3
POINTS = {"verified": 1.0, "late": 0.6, "mismatch": 0.0, "failed": 0.0}


def _parse(ts: Any) -> datetime:
    """An ISO-8601 timestamp (or datetime), as UTC truncated to milliseconds. A naive datetime is taken as UTC."""
    d = ts if isinstance(ts, datetime) else datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    d = d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
    return d.replace(microsecond=d.microsecond // 1000 * 1000)


def _iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def _body(r: dict) -> dict:
    """Accept a receipt body or a full {body, signature} object."""
    b = r.get("body")
    return b if isinstance(b, dict) and "claim" not in r else r


def score_v0(receipts: Iterable[dict], as_of: str | datetime, exclude_agent_ids: Iterable[str] = frozenset()) -> dict:
    """The score/v0 of ONE agent's receipts at `as_of`. Returns the output object of the formula (integers and strings only).

    - Window: `issued_at` in (as_of - 90 days, as_of].
    - A receipt another receipt in the input `supersedes` is dropped (the latest in a chain counts).
    - `unverifiable` receipts are counted in `unverifiable` and never scored. A verdict this formula does not know is ignored.
    - `exclude_agent_ids`: receipts whose `agent.id` is listed are dropped, so an internal agent never gets a score.
    - A `claimed_at` after `as_of` counts as age 0.
    """
    now = _parse(as_of)
    start = now - timedelta(days=WINDOW_DAYS)
    excluded = set(exclude_agent_ids)
    bodies = [_body(r) for r in receipts]
    bodies = [b for b in bodies if (b.get("agent") or {}).get("id") not in excluded]
    superseded = {b["supersedes"] for b in bodies if b.get("supersedes")}

    verdicts = {"verified": 0, "late": 0, "mismatch": 0, "failed": 0}
    unverifiable = 0
    counted: list[tuple[datetime, str, str, str, str]] = []  # claimed_at, receipt_id, action, target, verdict
    for b in bodies:
        if b.get("receipt_id") in superseded or not (start < _parse(b["issued_at"]) <= now):
            continue
        v = (b.get("verdict") or {}).get("value")
        if v == "unverifiable":
            unverifiable += 1
        elif v in POINTS:
            c = b["claim"]
            counted.append((_parse(c["claimed_at"]), str(b.get("receipt_id", "")), c["action"], c["target"], v))
            verdicts[v] += 1

    counted.sort(key=lambda t: (t[0], t[1]))
    rank: dict[tuple[str, str], int] = {}
    sum_w = sum_ws = 0.0
    for claimed_at, _rid, action, target, v in counted:
        k = rank[(action, target)] = rank.get((action, target), 0) + 1
        age = max(0.0, (now - claimed_at).total_seconds() / 86400)
        w = 0.5 ** (age / HALF_LIFE_DAYS) / math.sqrt(k)
        sum_w += w
        sum_ws += w * POINTS[v]
    raw = 100 * (sum_ws + PRIOR_K * PRIOR_P) / (sum_w + PRIOR_K)
    targets = len({t[3] for t in counted})
    return {
        "formula": FORMULA,
        "as_of": _iso(now),
        "window_days": WINDOW_DAYS,
        "score": int(Decimal(raw).quantize(Decimal(1), rounding=ROUND_HALF_UP)),
        "provisional": len(counted) < PROVISIONAL_MIN_COUNTED or targets < PROVISIONAL_MIN_TARGETS,
        "counted": len(counted),
        "unverifiable": unverifiable,
        "verdicts": verdicts,
        "distinct_targets": targets,
    }
