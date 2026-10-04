"""Compute the score/v0 reputation score (SPEC.md appendix) from a file of one agent's receipts.

    uv run score.py --as-of 2026-10-04T12:00:00Z receipts.json

`receipts.json` is a JSON array of receipt bodies (or full {body, signature} objects). Prints the score object as JSON.
Pass `--exclude AGENT_ID` (repeatable) to drop receipts of an agent that must not be scored.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2] / "core-python" / "src"))
from poaw_core import score_v0  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="score/v0 from an agent's receipts")
    ap.add_argument("receipts", help="JSON file: an array of receipt bodies or {body, signature} objects")
    ap.add_argument("--as-of", required=True, help="ISO-8601 timestamp the score is computed at")
    ap.add_argument("--exclude", action="append", default=[], help="agent id whose receipts are dropped (repeatable)")
    a = ap.parse_args(argv)
    receipts = json.loads(Path(a.receipts).read_text())
    if not isinstance(receipts, list):
        print("receipts file must be a JSON array", file=sys.stderr)
        return 2
    print(json.dumps(score_v0(receipts, a.as_of, set(a.exclude)), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
