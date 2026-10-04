# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=43", "rfc8785==0.1.4"]
# ///
"""Generate the score/v0 vectors under vectors/score/ (SPEC.md appendix). Separate from generate_vectors.py so the
conformance vectors never move.

    uv run oss/spec/tools/generate_score_vectors.py           # write vectors/score/
    uv run oss/spec/tools/generate_score_vectors.py --check   # fail if vectors/score/ differs

The receipts are minimal bodies: just the fields the formula reads. The three worked examples are checked here against the
numbers written in the spec (69, 66, 93) so the implementation cannot quietly redefine them.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2] / "core-python" / "src"))
from poaw_core import score_v0  # noqa: E402

OUT = Path(__file__).parents[1] / "vectors" / "score"
AS_OF = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)


def iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def rcpt(i: int, verdict="verified", target=None, age_days=0.0, issued_age=None, action="x.post.publish", **extra) -> dict:
    b = {"receipt_id": f"rcpt_{i:04d}", "issued_at": iso(AS_OF - timedelta(days=age_days if issued_age is None else issued_age)),
         "agent": {"id": "agent-example-1"},
         "claim": {"action": action, "target": target or f"x.com/example{i}", "claimed_at": iso(AS_OF - timedelta(days=age_days))},
         "verdict": {"value": verdict}}
    b.update(extra)
    return b


MIXED = [
    rcpt(1, "verified", "x.com/a", age_days=40),
    rcpt(2, "verified", "x.com/a", age_days=20),
    rcpt(3, "late", "x.com/b", age_days=10),
    rcpt(4, "mismatch", "x.com/c", age_days=5),
    rcpt(5, "failed", "x.com/a", age_days=3),
    rcpt(6, "unverifiable", "x.com/d", age_days=2),
    rcpt(7, "failed", "x.com/e", age_days=1),
    rcpt(8, "verified", "x.com/e", age_days=0.5, supersedes="rcpt_0007"),
    rcpt(9, "verified", "x.com/old", age_days=100, issued_age=90),   # issued exactly at the window's open edge: out
    rcpt(10, "verified", "x.com/f", age_days=95, issued_age=89),     # claimed long ago, issued inside the window: in
    rcpt(11, "verified", "x.com/g", age_days=0, issued_age=-1),      # issued after as_of: out
]

CASES = {
    "001-adr-three-targets": ("Three fresh verified receipts on three targets: the ADR example, 69, provisional.",
                              [rcpt(i) for i in range(3)], 69),
    "002-adr-one-target": ("Three fresh verified receipts on one target: repeats decay, 66, provisional.",
                           [rcpt(i, target="x.com/example") for i in range(3)], 66),
    "003-adr-thirty-targets": ("Thirty fresh verified receipts on thirty targets: 93, no longer provisional.",
                               [rcpt(i) for i in range(30)], 93),
    "004-mixed": ("All verdicts, recency, repeat decay, a superseded receipt, an unverifiable one, and both window edges.",
                  MIXED, None),
    "005-empty": ("No receipts: the prior alone, 50, provisional.", [], 50),
}


def main() -> int:
    files = {}
    for name, (desc, receipts, want) in CASES.items():
        got = score_v0(receipts, iso(AS_OF))
        if want is not None and got["score"] != want:
            print(f"{name}: spec says {want}, implementation says {got['score']}", file=sys.stderr)
            return 1
        files[f"{name}.json"] = json.dumps({"description": desc, "as_of": iso(AS_OF), "receipts": receipts, "expected": got},
                                           indent=2, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        stale = [n for n, t in files.items() if not (OUT / n).exists() or (OUT / n).read_text() != t]
        extra = sorted({p.name for p in OUT.glob("*.json")} - set(files)) if OUT.exists() else []
        if stale or extra:
            print(f"score vectors out of date: stale={stale} extra={extra}", file=sys.stderr)
            return 1
        print(f"score vectors up to date ({len(files)})")
        return 0
    OUT.mkdir(exist_ok=True)
    for n, t in files.items():
        (OUT / n).write_text(t)
    print(f"wrote {len(files)} score vectors to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
