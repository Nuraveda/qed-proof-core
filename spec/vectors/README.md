# Conformance vectors — poaw/0.1 and poaw/0.2

Every conforming checker MUST produce the `expected` result in `manifest.json` for every vector,
using `keys.json` as the issuer's key set.

- `manifest.json`: one entry per vector, with `description` and `expected` (`valid`, `verdict`, `achieved_trust_level`, and per-check results)
- `keys.json`: the issuer key set (§5.2). **The keys are the public RFC 8032 §7.1 test keys (TEST 1 and TEST 2). They are test-only.**
- `NNN-*.json`: the receipts and change entries
- `pipeline.example.json`: the pipeline document (SPEC §15) that manifest entries with a `pipeline` member are checked against. A checker passes it in as the optional pipeline input; without one, `policy` is reported `not_checked`.

The vectors cover a valid receipt for every verdict value, key validity windows (including a revoked key used before and after
revocation), tampering, a wrong or unknown key, claim-digest mismatch, schema violations, non-integer numbers, an unsupported
major version, and RFC 6962 inclusion proofs (first, middle and last leaf of an unbalanced tree, plus altered path and index).

**`poaw/0.2` (021–035):** a 0.2 receipt without a policy, a policy that checks out, one with no document to check against, a wrong digest, a wrong version, a policy on a 0.1 body, change entries (valid, tampered, wrong signature domain in both directions, missing policy, carrying a claim, unknown `entry_kind`) and change entries proven included in a log that also holds receipts. Vectors 001–020 are byte-for-byte what they were under 0.1.

**Public log (036–041):** listed in `manifest.json` under their own keys, so `vectors` is exactly what it was.
`tree_head_vectors` are signed tree heads (SPEC §8.5): a valid one, one with its `tree_size` altered, one signed under the receipt
domain, one with a fifth body field. The checker reports `{valid, checks: {shape, key, signature}}` against `keys.json`.
`consistency_vectors` are `GET /v1/log/consistency` responses (§8.4): a valid proof that a 3-leaf tree is a prefix of a 7-leaf tree,
and the same proof with a wrong `first_root`. `expected.valid` is the result of RFC 9162 §2.1.4.2 verification over
`(first, second, first_root, second_root, proof)`.

**Not covered offline:** anchor checks (§8.4) need a blockchain RPC, and attestation (trust level ≥ 3) needs a platform root of
trust. A receipt that claims level 2 without a verifiable anchor is reported at its *achieved* level, 1 (vector 016).

Regenerate with `uv run oss/spec/tools/generate_vectors.py`. CI runs it with `--check`, and it fails on any byte difference.
The generator asserts that the reference checker agrees with the intent written for each vector, so a checker bug can't
quietly redefine what the vectors mean.
