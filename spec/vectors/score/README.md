# score/v0 vectors

Test vectors for the reputation score `score/v0` (SPEC.md, "Appendix: reputation score v0"). Each file is
`{ "description", "as_of", "receipts": [...], "expected": {...} }`. An implementation MUST return `expected` exactly when
given `receipts` and `as_of` (and no excluded agents).

The receipts are minimal bodies carrying only the fields the formula reads: `receipt_id`, `issued_at`, `agent.id`,
`claim.{action,target,claimed_at}`, `verdict.value` and, where used, `supersedes`. Full `{body, signature}` receipts are
accepted too; the formula ignores everything else.

| file | covers |
|---|---|
| `001-adr-three-targets` | three fresh verified receipts on three targets: 69, provisional |
| `002-adr-one-target` | the same on one target: 66 (repeats decay) |
| `003-adr-thirty-targets` | thirty fresh verified on thirty targets: 93, not provisional |
| `004-mixed` | every verdict, recency, repeat decay, a superseded receipt, an unverifiable one, both window edges |
| `005-empty` | no receipts: the prior alone, 50 |

Regenerate with `uv run oss/spec/tools/generate_score_vectors.py` (`--check` in CI). Compute a score yourself with
`uv run oss/spec/tools/score.py --as-of <timestamp> receipts.json`.
