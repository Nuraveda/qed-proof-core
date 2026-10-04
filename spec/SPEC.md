# Proof of Agent Work (PoAW) — Receipt Specification

**Version:** `poaw/0.2` (draft; `poaw/0.1` receipts stay valid, see §16) · **Status:** Draft. Breaking changes are expected before 1.0. · **License:** Apache-2.0

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119.

## 1. Purpose

An AI agent **claims** it did something ("published a post", "pushed a commit", "sent an email").
A **verifier** independently checks the **destination** where that work was supposed to land and
records what it **observed**. A **receipt** is the signed, tamper-evident record of the claim, the
observation and the resulting **verdict**.

A receipt is meant to be checked **by anyone, without trusting the issuer's servers**. It needs
the issuer's public key, the log's inclusion proof and a public blockchain RPC.

This document defines the receipt format, how it is signed, how receipts are logged and anchored,
and what each verdict means. It does not define how any particular verifier talks to any
particular destination. Each verifier publishes its own profile (§9).

## 2. Terminology

| Term | Definition |
|---|---|
| **Agent** | The software that performed (or claims to have performed) the work. |
| **Claim** | The agent's statement of what it did. **Always untrusted input.** |
| **Destination** | The external system where the work should be observable (a repository, a social timeline, a mailbox, an HTTP endpoint). |
| **Verifier** | A versioned procedure that reads the destination and produces an observation. It is deterministic given the same destination state. |
| **Observation** | What the verifier saw, recorded as **facts**: identifiers, timestamps and fingerprints. Never content. |
| **Verdict** | The outcome of comparing the claim with the observation (§6). |
| **Issuer** | The party that ran the verifier and signed the receipt. It is identified by a public key. |
| **Log** | An append-only Merkle tree of receipts, operated by the issuer (§8). |
| **Anchor** | A public, timestamped commitment to a log root, e.g. an attestation on a blockchain (§8.4). |
| **Pipeline** | A declarative, versioned document that says what to prove, where, and what to do about the outcome (§15). |
| **Policy** | The identity of the pipeline version a receipt or change entry was produced under: `{pipeline_id, pipeline_version, digest}` (§15.2). |
| **Change entry** | A signed log entry recording an in-scope change at a destination that no claim explained (§14). |

## 3. Encoding

- Receipts are JSON (RFC 8259), encoded as UTF-8.
- **Canonicalisation:** every signature and hash in this spec is computed over the
  **JSON Canonicalization Scheme (JCS, RFC 8785)** serialisation of the object named. Implementations
  MUST canonicalise with an RFC 8785-conformant library, not by re-serialising with sorted keys.
- Timestamps are RFC 3339 strings in UTC with a `Z` suffix and at most millisecond precision, e.g. `2026-09-25T14:02:11.000Z`.
- Binary values (hashes, signatures, keys) are **base64url without padding** (RFC 4648 §5), unless noted otherwise.
- Hashes are SHA-256.
- Numbers MUST be integers within ±2^53. Floating-point values MUST NOT appear in a receipt (JCS number
  formatting of non-integers is a common source of cross-language disagreement).

## 4. The receipt object

A receipt has three top-level members, plus one optional fourth at trust level 3:

```json
{
  "body":      { … },   // the signed statement (§4.1)
  "signature": { … },   // over the body (§5)
  "proof":     { … },   // log inclusion and anchor (§8). NOT signed, and may be added later
  "attestation_document": "…"  // level 3 only: base64url(COSE_Sign1), the document body.attestation commits to (§7.1). NOT signed
}
```

`body` and `signature` are immutable once issued. `proof` is attached by the log and may be
extended over time (for example, when an anchor lands). It is verified on its own terms (§8), so it
doesn't need to be signed. `attestation_document` is likewise outside the signed body (so the signed message stays small),
but it cannot be swapped: the body commits to it by hash (§4.1, §7.1), so it is bound to the signature.

### 4.1 `body`

| Field | Type | Req. | Meaning |
|---|---|---|---|
| `spec_version` | string | MUST | `"poaw/0.1"` or `"poaw/0.2"`. A body that uses a member introduced in 0.2 (`policy`) MUST say `"poaw/0.2"`. An issuer that uses none MAY keep saying `"poaw/0.1"`. |
| `receipt_id` | string | MUST | Issuer-unique ID. RECOMMENDED form: `rcpt_` followed by a ULID. |
| `issued_at` | timestamp | MUST | When the issuer signed. |
| `issuer` | object | MUST | `{ "key_id": string, "name"?: string }`. `key_id` per §5.2. |
| `agent` | object | MUST | `{ "id": string, "erc8004"?: { "chain": string, "registry": string, "agent_id": string } }`. `id` is opaque to this spec. `chain` is a CAIP-2 ID (e.g. `eip155:8453`). |
| `operator` | string | MAY | Opaque ID of the party that runs the agent. |
| `claim` | object | MUST | §4.2 |
| `observation` | object | MUST | §4.3 |
| `verdict` | object | MUST | `{ "value": Verdict, "reason_code"?: ReasonCode }` (§6) |
| `trust_level` | integer | MUST | 1–4 (§7) |
| `attestation` | object | MAY | Required when `trust_level` ≥ 3. `{ "type": string, "document_sha256": string }`, e.g. `type: "aws-nitro-enclave"`. `document_sha256` is `base64url(SHA-256(document bytes))`; the document itself is the receipt's top-level `attestation_document` (§4), not part of the body. |
| `supersedes` | string | MAY | The `receipt_id` this receipt corrects. The old receipt remains valid as a record. Consumers SHOULD prefer the newest in a chain. |
| `policy` | object | MAY | `poaw/0.2`. The pipeline version that asked for this receipt: `{ "pipeline_id": string, "pipeline_version": integer, "digest": string }` (§15.2). |

Unknown members in `body` MUST be preserved (they are covered by the signature). Consumers
MUST reject a body whose `spec_version` major version they don't support. Checkers MUST accept `poaw/0.1` and `poaw/0.2`.

### 4.2 `claim`

| Field | Type | Req. | Meaning |
|---|---|---|---|
| `action` | string | MUST | Action name (§9.1), e.g. `"x.post.publish"`. |
| `target` | string | MUST | Where the work should land, in the form the action's profile defines (a repo slug, an account handle, a URL). |
| `params` | object | MUST | Action-specific parameters, per the profile. It MUST NOT contain content bodies. Use fingerprints (§4.4). May be `{}`. |
| `claimed_at` | timestamp | MUST | When the agent says the work happened. |
| `client_claim_id` | string | SHOULD | The submitter's idempotency key. |
| `claim_digest` | string | MUST | base64url(SHA-256(JCS(claim without `claim_digest`))). It binds the claim as submitted. |

### 4.3 `observation`

| Field | Type | Req. | Meaning |
|---|---|---|---|
| `verifier` | object | MUST | `{ "id": string, "version": string, "code_hash"?: string }`. `id` + `version` name the profile (§9). `code_hash` is REQUIRED at trust level ≥ 3 and identifies the exact build that ran (`sha384:` + PCR0 hex, §7.1). |
| `observed_at` | timestamp | MUST | When the decisive read of the destination happened. |
| `deadline_at` | timestamp | MUST | The latest time the verifier would wait for the outcome (§6.2). |
| `attempts` | integer | MUST | Number of reads of the destination. |
| `facts` | object | MUST | Verifier-defined, schema-constrained (§9.2). It MUST follow §4.4. |

### 4.4 Facts, fingerprints and privacy

`facts` records **what is needed to re-check the outcome and nothing more**:

- Allowed: destination identifiers (post ID, commit SHA, message ID), timestamps, status codes,
  counts, booleans, and **fingerprints**.
- **Not allowed:** content bodies (email text, post text, file contents), personal data beyond what
  the claim's `target` already names, and credentials of any kind.
- **Fingerprint:** `sha256:` + base64url(SHA-256(normalised content)), where *normalised* means: Unicode NFC,
  line endings converted to LF, trailing whitespace on each line removed, and leading or trailing blank lines
  removed. A profile MAY define a stricter normalisation, and if it does it MUST say so.

## 5. Signature

### 5.1 Algorithm

```
message   = "POAW-RECEIPT-V0" || 0x0A || JCS(body)      // domain-separated
signature = Ed25519-Sign(issuer_private_key, message)    // RFC 8032, pure Ed25519
```

A change entry (§14) is signed the same way under its own domain, `"POAW-CHANGE-V0" || 0x0A || JCS(body)`, so a signature
over one kind of entry can never verify as the other. A signed tree head (§8.5) has a third, `"POAW-TREE-HEAD-V0"`.

```json
"signature": { "alg": "Ed25519", "key_id": "<§5.2>", "value": "<base64url 64-byte signature>" }
```

`signature.key_id` MUST equal `body.issuer.key_id`. The domain prefix stops a receipt signature
from being valid as a signature over any other protocol's message.

### 5.2 Key IDs and key discovery

- `key_id = "ed25519:" + base64url(SHA-256(raw 32-byte public key))`
- An issuer publishes its keys at `https://<issuer-domain>/.well-known/poaw-keys.json`:
  ```json
  { "keys": [ { "key_id": "ed25519:…", "public_key": "<base64url 32 bytes>",
                "valid_from": "…Z", "revoked_at": null } ],
    "anchor_addresses": ["0x…"], "anchor_schemas": ["0x<EAS schema UID>"] }
  ```
  `verifier_builds` (optional; needed for level 3, §7.1) lists the enclave builds the issuer accepts:
  `[ { "code_hash": "sha384:<PCR0 hex>", "platform": "aws-nitro-enclave", "version": "…", "source": "<URL>",
  "published_at": "…Z" } ]`. A `code_hash` not listed there is `unknown_build`.
  `anchor_addresses` and `anchor_schemas` are what an anchor check (§8.4) accepts. An attestation from any other
  address, or under any other schema, does not anchor this issuer's log.
- A receipt is **signature-valid** if the key exists, the signature checks out, and
  `valid_from ≤ issued_at < revoked_at` (or `revoked_at` is null). A receipt issued after the key's
  `revoked_at` MUST be treated as invalid. Receipts issued earlier stay valid, and the log anchor (§8)
  proves they existed before the revocation.

## 6. Verdicts

### 6.1 Values

| `verdict.value` | Meaning | Counts toward reputation? |
|---|---|---|
| `verified` | The destination shows the claimed outcome, matching every field the profile requires, observed no later than `claimed_at` + the profile's tolerance. | Yes, positively |
| `late` | The outcome is present and matches, but it appeared after `claimed_at` + tolerance (and before `deadline_at`). | Yes, mildly negatively |
| `mismatch` | The destination shows an outcome for the target, but a required field differs (e.g. a different content fingerprint, the wrong branch). | Yes, negatively |
| `failed` | The verifier could read the destination, and the outcome was not present by `deadline_at`. | Yes, negatively |
| `unverifiable` | The verifier could not determine the outcome (§6.3). | **No.** It is never evidence for or against the agent |

### 6.2 Rules

1. **Fail toward `unverifiable`, never toward `verified`.** Any error, timeout, missing permission,
   rate limit or ambiguity MUST yield `unverifiable`, never `verified`.
2. **Blame only on evidence.** `failed` and `mismatch` REQUIRE a successful read of the destination.
   A destination that couldn't be read yields `unverifiable`, not `failed`. The agent is never penalised for the verifier's blind spot.
3. `verified`, `late`, `mismatch` and `failed` MUST carry facts sufficient to re-check them (§4.4).
4. Verdicts are **decided deterministically** from the claim, the facts and the profile's match rules.
   A language model MAY help turn free text into a structured claim, but MUST NOT decide a verdict.

### 6.3 Reason codes

`verdict.reason_code` SHOULD be present for everything except `verified`, and MUST be present for `unverifiable`:

| Code | Used with | Meaning |
|---|---|---|
| `not_found` | failed | The destination was read, and no matching outcome existed by the deadline |
| `content_mismatch` | mismatch | The fingerprint differs from the claim |
| `target_mismatch` | mismatch | The outcome exists, but under a different target (account, branch, recipient) |
| `observed_after_tolerance` | late | Present, but after the tolerance window |
| `no_connection` | unverifiable | The issuer holds no access to the destination for this target |
| `permission_denied` | unverifiable | Access exists but doesn't cover this read |
| `rate_limited` | unverifiable | The destination throttled every read until the deadline |
| `destination_unavailable` | unverifiable | The destination errored or timed out until the deadline |
| `unsupported_action` | unverifiable | No verifier profile exists for `claim.action` |
| `claim_ambiguous` | unverifiable | The claim lacks the fields the profile needs |
| `verifier_error` | unverifiable | An internal failure in the verifier |

## 7. Trust levels

| Level | Name | The issuer additionally provides | A checker can confirm |
|---|---|---|---|
| 1 | Signed | §5 signature | The issuer stated this, and it hasn't been altered |
| 2 | Anchored | §8 inclusion proof + anchor | …and it existed no later than the anchor time. It can't be backdated or silently deleted |
| 3 | Attested | `attestation` + `observation.verifier.code_hash` | …and a specific, published verifier build produced the observation inside a hardware enclave |
| 4 | Web-proven | a zero-knowledge TLS proof inside `attestation` | …and the facts came from the destination's TLS session, without trusting hardware |

`trust_level` is the issuer's claim about which of these it provides. Checkers MUST compute the
**achieved** level from what actually verifies, and MUST report the lower of the two.

### 7.1 Attested observations (level 3, `aws-nitro-enclave`)

At level 3 the issuer runs the verifier inside an AWS Nitro enclave and the enclave, not the issuer, vouches for what was
observed. The receipt carries:

- `trust_level: 3`;
- `observation.verifier.code_hash = "sha384:" + lowercase hex(PCR0)`, the measurement of the enclave image;
- `attestation = { "type": "aws-nitro-enclave", "document_sha256": base64url(SHA-256(document bytes)) }` in the body, where the
  document is the COSE_Sign1 the enclave's Nitro Security Module issued. The document itself (about 6 KB once encoded) travels
  beside the body as the receipt's top-level `attestation_document` (base64url), the way `proof` does, so that the signed
  message stays small: pure Ed25519 over a KMS-held key accepts at most 4096 bytes. Everything else (issuer signature, log,
  anchor) is as at levels 1 and 2.

**The statement.** The enclave attests to this object, built from the receipt body and nothing else:

```json
{ "claim_digest": body.claim.claim_digest,
  "verifier": { "id": body.observation.verifier.id, "version": body.observation.verifier.version },
  "observed_at": body.observation.observed_at,
  "facts": body.observation.facts,
  "verdict": body.verdict }
```

`verdict` and `facts` are copied exactly as they appear in the body. `user_data = SHA-256(JCS(statement))` (32 bytes) is placed
in the attestation document; `nonce` is unused. A different verdict, facts, time, verifier or claim gives a different digest.

**Checking** (`trust_level ≥ 3` and `attestation.type == "aws-nitro-enclave"`):

1. Take the document from the receipt's top-level `attestation_document`. It MUST be present, and
   `base64url(SHA-256(decoded bytes))` MUST equal `body.attestation.document_sha256`. Decode it as a COSE_Sign1 (CBOR tag 18, or the bare four-element array). The protected header is `{1: -35}`
   (ES384). The payload is a CBOR map with `module_id`, `digest` (`"SHA384"`), `timestamp` (milliseconds), `pcrs` (integer to
   bytes), `certificate` (DER), `cabundle` (DER list), `user_data`, and optionally `public_key` and `nonce`.
2. `cabundle[0]` MUST be the AWS Nitro Enclaves root: the certificate whose DER has SHA-256
   `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b` (shipped as `nitro-root.pem`). The chain
   `cabundle[0] … cabundle[n]`, then `certificate`, MUST verify: each certificate signed by the one before it, every
   issuing certificate a CA (basic constraints, path length respected), every certificate valid at `timestamp`.
3. The COSE signature MUST verify with `certificate`'s P-384 public key (ECDSA, SHA-384, raw `r‖s`) over the
   Sig_structure `["Signature1", protected, h'', payload]`.
4. `pcrs[0]` MUST equal the bytes of `code_hash` after `sha384:`, and `user_data` MUST equal the statement digest
   recomputed from the receipt body.
5. `code_hash` MUST appear in the issuer's `verifier_builds` (§5.2), the builds it publishes as accepted.
6. If any rule fails, the achieved level is at most 2 and the checker reports why, with one of `attestation_invalid`
   (steps 1 and 3, an absent `attestation_document`, or a hash that does not match), `attestation_chain` (step 2), `pcr_mismatch` and `statement_mismatch` (step 4) or `unknown_build` (step 5).
   A failed attestation does not make the receipt's signature invalid.

A checker takes no trust-anchor input other than the pinned root; a way to replace it is for tests only. Levels are
cumulative (§7): the achieved level is 3 only when level 2 is achieved (inclusion and a verified anchor) **and** every
rule above holds. A checker that cannot check the anchor (no RPC) still reports `attestation` true, with the achieved
level it could reach without the anchor.

## 8. Log and anchoring

### 8.1 Leaves

`leaf_hash = SHA-256( 0x00 || JCS({ "body": body, "signature": signature }) )`

This holds for every kind of entry in the log: receipts and change entries (§14) are leaves of the same tree.

The log is an RFC 6962-style Merkle tree. Interior nodes are `SHA-256( 0x01 || left || right )`.

### 8.2 `proof`

```json
"proof": {
  "log_id": "<base64url SHA-256 of the log's public identifier>",
  "leaf_index": 88213,
  "tree_size": 88240,
  "root_hash": "<base64url>",
  "inclusion": ["<base64url>", "…"],
  "anchor": { "chain": "eip155:8453", "scheme": "eas", "uid": "0x…", "tx_hash": "0x…", "tree_size": 88240 }
}
```

`anchor` MAY be absent (trust level 1, or level 2 before the anchor lands). Absence is a limitation of the
proof. It does not make the receipt invalid.

### 8.3 Checking inclusion

The checker recomputes `leaf_hash`, then runs the RFC 6962 audit-path verification with
`leaf_index`, `tree_size` and `inclusion`, and MUST obtain exactly `root_hash`.

### 8.4 Checking the anchor (scheme `eas`)

The anchor is an Ethereum Attestation Service attestation on `anchor.chain`, from an attester address
the issuer publishes in `poaw-keys.json` (`"anchor_addresses": [...]`). Its data MUST decode (per the
issuer's published schema) to a `(log_id, tree_size, root_hash, …)` that equals `proof.log_id`,
`anchor.tree_size` and a root the checker can connect to `proof.root_hash`:

- If `anchor.tree_size == proof.tree_size`, the roots MUST be equal.
- Otherwise the checker MUST obtain an RFC 6962 **consistency proof** between the two sizes (`PROOF(m, D[n])` with `m` the
  smaller size) and MUST verify it (RFC 9162 §2.1.4.2). The smaller tree's root is the old root and the larger tree's root is
  the new root; one of them is the attested root and the other is `proof.root_hash`, whichever way round the sizes fall. The
  checker takes both roots from the attestation and from the receipt, never from the consistency proof's own response. The
  proof comes from the issuer's `GET /v1/log/consistency` (§8.6), or is supplied alongside the receipt. If the checker cannot
  obtain one, the anchor is unproven (`consistency_proof_required`), never a pass.

The attestation's block timestamp is the receipt's **proven-by time**.

### 8.5 Signed tree head

An issuer MAY publish a signed statement of the log's current size and root, so anyone can hold it to a single history.

```json
{
  "body": { "log_id": "<base64url, as in §8.2>", "tree_size": 88240, "root_hash": "<base64url>", "issued_at": "2026-09-25T14:05:00.000Z" },
  "signature": { "alg": "Ed25519", "key_id": "<§5.2>", "value": "<base64url 64-byte signature>" }
}
```

```
message = "POAW-TREE-HEAD-V0" || 0x0A || JCS(body)      // its own domain, so it never verifies as a receipt or change entry
```

A checker MUST reject a tree head unless:

- `body` has exactly the four fields above, `tree_size` is a non-negative integer, and the other three are strings;
- `signature.alg` is `Ed25519` and `signature.key_id` names a key in the issuer's key set that is valid at `body.issued_at`
  (§5.2: `valid_from <= issued_at`, and not revoked at or before it); and
- the signature verifies over the message above.

To check that a receipt's tree belongs to a head, the checker requires `proof.log_id == body.log_id` and
`proof.tree_size <= body.tree_size`, then: equal sizes need equal roots, otherwise a consistency proof (§8.4) from
`proof.root_hash` to `body.root_hash` MUST verify. A head that is older than the receipt's tree, or a proof that does not
verify, is a failure.

### 8.6 Public log endpoints (informative)

An issuer that runs a public log serves these over `GET`, free and without authentication, and answers cross-origin reads.
Hashes are base64url (§3). They are a convenience for checkers: nothing in §8.3–§8.5 depends on trusting them.

- `GET /v1/log/head` returns `{ "tree_head": <§8.5 object>, "anchor": null | { "chain", "scheme", "uid", "tx_hash", "tree_size", "root_hash", "block_number", "block_time" } }`, the latest landed anchor being the one reported.
- `GET /v1/log/consistency?first=M&second=N` (`0 < M <= N <=` current size) returns `{ "log_id", "first", "second", "first_root", "second_root", "proof": ["<b64u>", …] }`; `proof` is empty when `M = N`.
- `GET /v1/log/proof?leaf_index=I&tree_size=N` returns `{ "log_id", "leaf_index", "tree_size", "leaf_hash", "root_hash", "inclusion": ["<b64u>", …] }`.
- `GET /v1/log/anchors?limit=&before=` returns `{ "anchors": [ … newest first … ], "next": <tree_size> | null }`.
- `GET /v1/log/entries?start=&limit=` returns `{ "tree_size", "entries": [{ "leaf_index", "leaf_hash", "created_at" }], "next": <index> | null }`. Entries are hashes only; the log does not list receipt ids.

## 9. Actions and verifier profiles

### 9.1 Action names

`<domain>.<object>.<event>`, lowercase ASCII, e.g. `github.commit.push`, `github.pr.open`,
`github.checks.pass`, `http.url.status`, `x.post.publish`, `gmail.message.send`. New actions are added by
publishing a profile. An action name is never reused with a different meaning.

### 9.2 Profiles

Each verifier publishes a profile (a document plus a JSON Schema) defining:

1. **Accepted claim shape:** the `target` format and the `params` schema.
2. **Facts schema:** exactly which `facts` fields it records (under §4.4).
3. **Match rules:** the precise comparison that yields `verified`, `mismatch` and `failed`.
4. **Tolerance and deadline:** the default windows for `late` and for giving up.
5. **Required access:** the minimum read-only permission at the destination.

A profile is identified by `id` + `version`. Any change to (1)–(4) is a new version. A receipt is always
judged by the version recorded in it.

The profiles for the reference verifiers are published in [`profiles/`](profiles/), one document per action.

## 10. Checking a receipt (summary for implementers)

1. Parse. Reject an unknown major `spec_version`.
2. Resolve `issuer.key_id` from the issuer's key set, check the validity window, and verify the §5 signature.
3. Recompute `claim.claim_digest`.
4. If `proof` is present, verify inclusion (§8.3), and the anchor if present (§8.4).
5. If `trust_level ≥ 3`, verify `attestation` per §7.1: the receipt's `attestation_document` against
   `body.attestation.document_sha256`, the COSE document and its certificate chain to the pinned
   platform root, `pcrs[0]` = `code_hash`, `user_data` = the recomputed statement digest, and `code_hash` in the issuer's
   `verifier_builds`. On failure the achieved level is at most 2, with the §7.1 reason.
6. Report: signature ✓/✗, inclusion ✓/✗/absent, anchor ✓/✗/absent (with proven-by time), **achieved** trust
   level, and the verdict. A checker MUST NOT present a receipt as valid if step 2 fails.
7. If `body.policy` is present, report `policy`: `not_checked` without the pipeline document, otherwise ✓/✗ per §15.2.
   A failed policy check makes the receipt invalid. An entry with `body.entry_kind` = `"change"` is checked per §14.3.

## 11. ERC-8004 mapping (informative)

When published to an ERC-8004 Validation Registry, `validationResponse` SHOULD use:
`verified` → 100, `late` → 50, `mismatch` → 0, `failed` → 0, and `unverifiable` → **no response is posted**.
The evidence URI SHOULD resolve to the full receipt including `proof`. This mapping is provisional until
the ERC-8004 draft stabilises.

## 12. Security considerations

- **A receipt proves what the issuer observed, not absolute truth.** Trust levels 3 and 4 narrow what the issuer could fake.
- **Key compromise:** revoke the key in `poaw-keys.json`. Receipts anchored before the revocation remain provable (§5.2).
- **Log forks:** an issuer showing different roots to different parties is detected by consistency proofs
  against the public anchor. Checkers SHOULD verify against the anchor, not only the issuer's API.
- **Replay:** `receipt_id` is unique per issuer, and `claim_digest` binds the exact claim.
- **Privacy:** §4.4 is normative. A receipt carrying content bodies does not conform.

## 13. Test vectors

`vectors/` holds receipts and change entries with expected checker outcomes: valid at each trust level, tampered body,
wrong key, revoked key, bad inclusion path, anchor/root mismatch, every verdict value and every reason code, and (from
`poaw/0.2`) policy digests, change entries, and a signature moved across domains. The manifest also lists signed tree heads
(§8.5, `tree_head_vectors`) and consistency proofs (§8.4, `consistency_vectors`) under their own keys.
`attestation_vectors` (§7.1) are level-3 receipts built on a deterministic test certificate chain (never AWS): a valid one,
a wrong root, a tampered payload, a PCR mismatch, a statement mismatch, an unknown build and a document that does not match the hash the body commits to. Each names the `keyset`
(`keys-l3.json`, carrying `verifier_builds`) and the test root `nitro_root` (`nitro-test-root.pem`) a checker is given in
place of the AWS root, which tests may do and real checks may not.
Every conforming implementation MUST produce the expected outcome for every vector.

## 14. Change entries (`poaw/0.2`)

A **change entry** records a change at a destination that fell inside a pipeline's scope (§15) and that **no claim
explained**. It answers "what did the agent do that it never reported?". It is not a verdict on a claim, so it is not a
receipt. It lives in the same log, under the same keys, with the same inclusion proof and anchoring (§8).

### 14.1 `body`

A change entry has the same three top-level members as a receipt (`body`, `signature`, `proof`). Its `body` is:

| Field | Type | Req. | Meaning |
|---|---|---|---|
| `spec_version` | string | MUST | `"poaw/0.2"` |
| `entry_kind` | string | MUST | `"change"`. A body without `entry_kind` is a receipt. |
| `change_id` | string | MUST | Issuer-unique ID. RECOMMENDED form: `chg_` followed by a ULID. |
| `issued_at` | timestamp | MUST | When the issuer signed. |
| `issuer` | object | MUST | As in §4.1. |
| `connector` | string | MUST | The destination system, lowercase, e.g. `"github"`. |
| `event` | string | MUST | The kind of destination event, in the form of an action name (§9.1), e.g. `"github.commit.push"`. |
| `target` | string | MUST | Where the change happened, in the form `event`'s profile defines (a repo slug, an account ID). |
| `fingerprint` | string | MUST | The destination's own identifier for the change (a commit SHA, a change-log entry ID), or a §4.4 fingerprint. |
| `seen_at` | timestamp | MUST | When the watcher read the change from the destination. |
| `occurred_at` | timestamp | MAY | When the destination says the change happened. |
| `facts` | object | MUST | Verifier-defined, following §4.4. |
| `watcher` | object | MUST | `{ "id": string, "version": string, "code_hash"?: string }`. The profile (§9) that read the change. `code_hash` is REQUIRED at trust level ≥ 3. |
| `policy` | object | MUST | The pipeline version that was watching (§15.2). |
| `trust_level` | integer | MUST | 1–4 (§7), with the same meaning as for receipts. |
| `attestation` | object | MAY | Required when `trust_level` ≥ 3, as in §4.1. |

A change entry MUST NOT carry `claim`, `observation` or `verdict`. There was no claim, and the entry makes no judgement about
the agent: it states that a change happened and was not reported within the pipeline's grace period.

### 14.2 Rules

1. **Evidence comes from the destination.** `fingerprint`, `occurred_at` and `facts` are what the watcher read, never
   anything an agent supplied.
2. **Append-only.** A change entry is never edited or removed. If a claim later covers the same change, that claim's receipt
   is a separate entry. Consumers MAY link the two by `target` and `fingerprint`.
3. **No blame without a read.** A watcher that could not read the destination records nothing. It does not guess that a
   change happened (compare §6.2 rule 2).
4. **Privacy.** §4.4 applies to `facts` and `fingerprint`: identifiers, timestamps and fingerprints, never content.

### 14.3 Checking a change entry

Steps 1, 2, 4 and 5 of §10 apply, using the domain in §5.1 for the signature and `body.issued_at` for the key's validity
window. Step 3 (the claim digest) does not apply. Step 7 applies to `policy`. The report names the kind (`"entry_kind":
"change"`) and has no verdict.

## 15. Pipelines and policy (`poaw/0.2`)

### 15.1 The pipeline document

A **pipeline** is a JSON document, described by [`schema/pipeline.schema.json`](schema/pipeline.schema.json), that says:
which **connector** (a read-only connection to one destination) and target, what **triggers** it (`claim`, an agent's
report; `watch`, the destination's own change history), which events are in scope (**filter**), which published verifier
profile (§9.2) judges them and any **extra conditions** that narrow it (**check**), and what to do about the outcome
(**outcomes**: a receipt, and alerts).

The document follows §3: integers only, JCS-canonicalised for hashing. Its `id` and `version` are inside the document, so
its digest binds them. Editing a pipeline creates a new `version`. A published version is never changed.

### 15.2 The `policy` object

```json
"policy": { "pipeline_id": "ads-budget-changes", "pipeline_version": 3, "digest": "<base64url SHA-256>" }
```

`digest = base64url(SHA-256(JCS(pipeline document)))`, the same construction as `claim_digest` (§4.2). A receipt or change
entry carrying a `policy` therefore names the exact rule that asked for it.

A checker that is also given the pipeline document MUST check that (a) the document is valid against the pipeline schema,
(b) `document.id` equals `policy.pipeline_id` and `document.version` equals `policy.pipeline_version`, and (c) the digest
equals `policy.digest`. All three must hold for `policy` to be reported as passing. Without the document the checker
reports `policy` as `"not_checked"`, which does not invalidate the receipt. The issuer need not publish the document: the
digest lets its owner show which rule applied without disclosing it to everyone else.

### 15.3 Rules that keep pipelines honest

1. **Facts come only from the destination.** A pipeline document MUST NOT reference a claim anywhere. Conditions
   name only fields of the destination's own event (`event.*`) or of the facts the profile recorded (`observed.*`), and
   compare them to literal values. The claim says what to look for. The destination says what happened. The schema makes
   this structural: there is no operand that can hold a claim value.
2. **Conditions only narrow.** An extra condition can keep an event out of scope or turn a would-be `verified` into a
   non-`verified` verdict. It can never turn a failed profile match into `verified` (§6.2 rule 1).
3. **No user code.** A pipeline is data. It has no expressions beyond the comparisons in the schema.

## 16. Changes from `poaw/0.1`

`poaw/0.2` is a minor version. Every `poaw/0.1` receipt is still valid, byte for byte, and checkers MUST keep accepting it.
Added: the optional `policy` member (§4.1, §15.2); the change entry (§14) with its own signature domain (§5.1); the pipeline
document (§15). A receipt that uses none of these MAY keep saying `poaw/0.1`.

Added later, without a version change (existing receipts are unaffected): the level-3 attestation rules (§7.1), the optional
`verifier_builds` key-set member (§5.2), and `code_hash` as `sha384:` plus 96 hex digits (a PCR0) as well as `sha256:`.

Changed before release, without a version change: `body.attestation` is `{ type, document_sha256 }` and the document moved to the
receipt's top-level `attestation_document` (§4, §7.1), because the full document (about 6 KB) exceeded the 4096-byte message limit of
a KMS-held pure Ed25519 signing key. No level-3 receipt had been issued in the earlier shape.

Added later, without a version change (nothing in a receipt differs): the signed tree head with its own signature domain
(§5.1, §8.5), the public log endpoints (§8.6), and checkers verifying a consistency proof where an anchor is at a different
tree size than the receipt's proof (§8.4), which used to be left unproven.

## Appendix: reputation score v0 (`score/v0`)

*Informative.* Nothing in a receipt depends on it. It is a published, deterministic function from one agent's receipts to a
number, so that anyone holding the receipts gets the same score. There is no model and there are no hidden inputs.
`poaw_core.score_v0` is the reference implementation; `vectors/score/` holds test vectors; `tools/score.py` computes a score
from a file of receipts.

**Inputs.** The agent's receipt bodies with `issued_at` in the window `(as_of − 90 days, as_of]`. A receipt that another
receipt names in `supersedes` is dropped, so only the latest in a chain counts. A receipt with verdict `unverifiable` is
never scored (§6.1); it is reported in `unverifiable`. Receipts of agents the publisher excludes (for example its own test
agents) are not scored.

**Points** `s` per receipt by `verdict.value`: `verified` 1.0, `late` 0.6, `mismatch` 0, `failed` 0.

**Weight** `w = r × d`.
- Recency `r = 0.5 ^ (age_days / 30)`, where `age_days` is the time from `claim.claimed_at` to `as_of` in days (fractional;
  a `claimed_at` after `as_of` counts as 0).
- Repeats `d = 1 / sqrt(k)`, where `k` is the receipt's rank (1, 2, 3, …) among the counted receipts with the same
  `(claim.action, claim.target)`, ordered by `claim.claimed_at` and then `receipt_id` (string order).

**Score.** `score = round_half_up(100 × (Σ w·s + K·P) / (Σ w + K))` with `K = 5` and `P = 0.5`, so no receipts score 50.
Rounding is half up (a value of exactly `x.5` goes to the next integer), not half to even. The sums run in order of `claimed_at`
then `receipt_id`, with IEEE 754 doubles.

**Provisional.** The score is provisional while `counted < 30` or `distinct_targets < 3` (distinct `claim.target` values among
counted receipts). A provisional score MUST be presented with that word and its receipt count.

**Output.** `{ "formula": "score/v0", "as_of": <UTC, millisecond precision>, "window_days": 90, "score": <integer>,
"provisional": <bool>, "counted": <int>, "unverifiable": <int>, "verdicts": { "verified", "late", "mismatch", "failed" },
"distinct_targets": <int> }`, where `counted` is the number of scored receipts and `verdicts` counts them by verdict. A
change to any constant or rule is a new formula id (`score/v1`); `score/v0` results stay reproducible.

Worked examples: three fresh `verified` receipts on three targets score 69 (66 if all on one target); thirty on thirty
targets score 93.
