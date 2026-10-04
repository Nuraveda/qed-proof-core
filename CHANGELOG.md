# Changelog

All notable changes to `qed-proof-core` (the PoAW specification, the `poaw_core` reference library, the reference checker
and the self-hostable verification node) are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/).

The client libraries have their own changelogs: [Python SDK](https://github.com/Nuraveda/qed-proof-python/blob/main/CHANGELOG.md),
[JavaScript SDK and CLI](https://github.com/Nuraveda/qed-proof-js/blob/main/CHANGELOG.md) and
[MCP server](https://github.com/Nuraveda/qed-proof-mcp/blob/main/CHANGELOG.md).

## [Unreleased]

## [0.6.2] - 2026-10-04

### Changed

- README: screenshots of the public log and of a receipt checked in the browser, and a short section on the public log API.

## [0.6.1] - 2026-10-04

### Changed

- README: opens with a 20-second product video (a silent loop, linking to the full video with sound).

## [0.6.0] - 2026-10-04

The log becomes publicly readable and checkable: a signed tree head, consistency proofs, and a first reputation score.

### Added

- Spec: a **signed tree head** (SPEC §8.5), a signature over the log's current size and root, so anyone can pin what the log
  looked like at a point in time.
- Spec: the **public log endpoints** (SPEC §8.6): `/v1/log/head`, `/v1/log/consistency`, `/v1/log/proof`, `/v1/log/anchors`
  and `/v1/log/entries`. They are free to read and need no API key. Receipt inclusion proofs now carry the anchor's block
  number and time.
- Spec: a reputation score, `score/v0`, defined in an appendix, with reference vectors under `spec/vectors/score/`.
- Spec: conformance vectors 036 to 041 covering tree heads and consistency proofs.
- Reference checker: `check.py --head`, `--consistency` and `--issuer` check a receipt against a signed tree head and
  consistency proofs; an anchor at a different tree size is connected to the receipt by a consistency proof.
- `tools/score.py`: computes `score/v0` from a set of entries.
- `poaw_core`: `score_v0`, and functions to sign and verify tree heads.

## [0.5.0] - 2026-10-01

### Added

- Spec `poaw/0.2` (SPEC §14 and §15): **change entries**, signed log entries for a change at a destination that no claim
  explained, and **pipeline policies**, a pipeline document whose digest a receipt or change entry can carry in `policy`.
  Receipts that use neither stay `poaw/0.1`.
- JSON Schemas for change entries and pipeline documents, and an updated receipt schema.
- Conformance vectors 021 to 035 (policy checked, not checked, bad digest, version mismatches; change entries valid,
  tampered, signed under the wrong domain, with and without inclusion proofs) and an example pipeline document.
- Reference checker: verifies change entries and checks `policy` against a pipeline document.

### Security

- The node refuses request bodies over the size limit even when they arrive chunked, where a `Content-Length` check cannot
  see them.

### Fixed

- Anchoring claims its send atomically in the database and allows one anchor in flight, so overlapping ticks can no longer
  race for the same transaction.

## [0.4.0] - 2026-09-28

### Added

- Node: an endpoint listing the connections a workspace has set up.

## [0.3.0] - 2026-09-26

### Added

- Node: **Slack** (`slack.message.post`) and **X** (`x.post.publish`) verifiers, alongside the existing GitHub and HTTP ones.
- Node: listing a workspace's claims, with a cursor.
- Spec: an action profile document for each live action (`github.commit.push`, `github.pr.open`, `github.checks.pass`,
  `slack.message.post`, `x.post.publish`) under `spec/profiles/`.

## [0.2.4] - 2026-09-26

### Security

- Node: behind a CDN the caller's IP is read from a viewer-IP header only when the request also carries a shared edge secret
  (`POAW_TRUSTED_EDGE_SECRET`). Without the secret the header is ignored, so a direct caller cannot forge their IP to
  dodge the per-IP rate limit.

## [0.2.3] - 2026-09-26

Maintenance release. Code of Conduct wording.

## [0.2.2] - 2026-09-26

Maintenance release. Documentation updates (README and contributing guide).

## [0.2.1] - 2026-09-26

### Added

- Community files: Code of Conduct, contributor licence agreement, `NOTICE` and a pull request template.

## [0.2.0] - 2026-09-26

### Added

- **Self-hosting**: `docker compose up` runs a verification node with its own database, and a smoke test that turns a real
  claim into a receipt the reference checker accepts. A `poaw-node` command-line entry point and database schema ship with it.
- On-chain anchoring: the node periodically anchors the log's root as an Ethereum Attestation Service attestation, and the
  checker's anchor check reads it back over JSON-RPC.
- A much fuller README.

## [0.1.1] - 2026-09-26

Maintenance release. Adds continuous integration.

## [0.1.0] - 2026-09-26

Initial release.

### Added

- The PoAW specification (`poaw/0.1`): claims, receipts, a signed append-only Merkle log, and its JSON Schema.
- `poaw_core`, the reference library: JCS canonicalisation, Ed25519 signing and Merkle inclusion proofs.
- The reference checker (`check.py`, `anchor_check.py`) and a conformance vector suite with a generator.
- A verification node with GitHub and HTTP verifiers, a verdict engine and a receipt builder.

[Unreleased]: https://github.com/Nuraveda/qed-proof-core/compare/v0.6.0...HEAD
[0.6.2]: https://github.com/Nuraveda/qed-proof-core/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/Nuraveda/qed-proof-core/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Nuraveda/qed-proof-core/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Nuraveda/qed-proof-core/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Nuraveda/qed-proof-core/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Nuraveda/qed-proof-core/compare/v0.2.4...v0.3.0
[0.2.4]: https://github.com/Nuraveda/qed-proof-core/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/Nuraveda/qed-proof-core/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/Nuraveda/qed-proof-core/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Nuraveda/qed-proof-core/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Nuraveda/qed-proof-core/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Nuraveda/qed-proof-core/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Nuraveda/qed-proof-core/releases/tag/v0.1.0
