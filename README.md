<div align="center">

# 🧾 POAW — Proof of Agent Work

### Receipts for AI agents: what an agent **claimed** it did, checked against what the **destination** actually shows.

<a href="https://qedproof.site/media/qed-proof-in-20s.mp4"><img src="https://qedproof.site/media/qed-proof-in-20s.gif" alt="QED Proof in 20 seconds: an agent reports it pushed a1b2c3 to main, QED Proof reads GitHub's own commit list, finds no such commit, and issues a signed Failed receipt." width="800"></a>

<sub>20 seconds, silent loop · <a href="https://qedproof.site/media/qed-proof-in-20s.mp4">watch with sound</a></sub>

An open protocol and a **self-hostable node**. An agent says *"I pushed commit `abc123` to `main`"*; the node asks
GitHub itself, decides a verdict, **signs a receipt**, appends it to an **append-only Merkle log**, and anchors the
log's root on a **public chain**. Anyone can check a receipt later — offline, without trusting whoever issued it.

[![Spec: poaw/0.2](https://img.shields.io/badge/spec-poaw%2F0.2%20draft-6d28d9.svg)](spec/SPEC.md)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE-APACHE)
[![Node: AGPL v3](https://img.shields.io/badge/node-AGPL_v3-blue.svg)](node/LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Built with FastAPI](https://img.shields.io/badge/built%20with-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![CI](https://img.shields.io/github/actions/workflow/status/Nuraveda/qed-proof-core/ci.yml?branch=main&label=CI)](https://github.com/Nuraveda/qed-proof-core/actions)
[![Discord](https://img.shields.io/badge/Discord-community%20%26%20support-5865F2.svg?logo=discord&logoColor=white)](https://discord.gg/9yhJs3EdCx)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Stars](https://img.shields.io/github/stars/Nuraveda/qed-proof-core?style=social)](https://github.com/Nuraveda/qed-proof-core/stargazers)

**[Hosted](https://qedproof.site)** · **[Discord](https://discord.gg/9yhJs3EdCx)** · **[Spec](spec/SPEC.md)** · **[How it works](#how-it-works)** · **[Quickstart](#quickstart-self-host)** · **[Verifiers](#what-it-can-check-today)** · **[Check a receipt](#check-a-receipt-yourself)** · **[Contributing](CONTRIBUTING.md)**

</div>

---

> **🟢 Open source · Apache-2.0 (spec, core) + AGPL-3.0 (node) · open-core.** The protocol, the checker and the full
> node are here — read them, run them, extend them. A managed, multi-team **hosted service**
> ([qedproof.site](https://qedproof.site)) with a console, alerts and GitHub connections is the paid product, and it
> runs **this same node code**. Same model as Supabase: open core, paid cloud.

Agents report their own success, and those reports are often wrong: the commit is on another branch, the PR was never
opened, the page returns 404. Logs and traces record **what the agent said**. POAW records **what the destination
shows**, in a form a third party can verify.

**Where it sits next to things you already use:**

| | Records | Who can check it later |
|---|---|---|
| Agent tracing / observability | the agent's own steps and outputs | you, inside your tooling |
| Code review bots | an opinion on a diff | whoever reads the comment |
| Supply-chain attestations (SLSA, in-toto) | how an artifact was built | anyone with the attestation |
| **POAW** | **whether the claimed outcome exists at the destination** | **anyone with the receipt: signature, log inclusion, and on-chain anchor** |

## Contents

- [How it works](#how-it-works) · [The public log](#the-public-log)
- [Verdicts and trust levels](#verdicts-and-trust-levels)
- [What it can check today](#what-it-can-check-today)
- [Quickstart (self-host)](#quickstart-self-host)
- [Send a claim](#send-a-claim)
- [Check a receipt yourself](#check-a-receipt-yourself)
- [Configuration](#configuration)
- [Repository layout](#repository-layout)
- [Hosted vs self-hosted](#hosted-vs-self-hosted)
- [Community and support](#community-and-support)
- [License](#license) · [Contributing](#contributing) · [Security](#security)

---

## How it works

```
  your agent                         the POAW node                               anyone, later
  ──────────                         ─────────────                               ─────────────
  "I pushed abc123 to main"   ──▶  1. claim (API key)
   POST /v1/claims                  2. ask the DESTINATION itself ──▶ GitHub / the URL
                                       (never the agent's report)
                                    3. verdict: verified · late · mismatch
                                                · failed · unverifiable
                                    4. sign the receipt (Ed25519)
                                    5. append to the Merkle log  ─┐
                                    6. anchor the root on Base   ─┴──▶  GET /v1/receipts/<id>
                                       (EAS attestation)                check: signature ✓
                                                                             log inclusion ✓
                                                                             chain anchor ✓
```

Principles the code enforces:

- **Evidence comes from the destination**, never from the agent's own report.
- A verifier error, timeout or missing permission gives **`unverifiable`**, never `verified`.
- Receipts are **append-only** (the database refuses updates and deletes). They store **fingerprints, not content**.

### The public log

Every receipt is a leaf in the log, and the log is free to read: no account, no key, open to any website. The node
serves a signed tree head, inclusion and consistency proofs, the anchor history and an entry ledger that shows hashes
only, so nobody's claims are exposed (`GET /v1/log/head`, `/consistency`, `/proof`, `/anchors`, `/entries`; spec §8.5–§8.6).

```bash
curl -s https://api.qedproof.site/v1/log/head    # the hosted node's signed head and latest anchor
```

<p align="center">
  <a href="https://qedproof.site/log/"><img src="https://qedproof.site/media/readme-log.png" alt="The public log on qedproof.site: the signed head (9 entries, its root hash and signing key), anchored up to entry 9 on Base Sepolia (testnet) at block 47,309,207, the anchors table, and the entry ledger of leaf hashes." width="760"></a>
  <br><sub>The hosted node's log at <a href="https://qedproof.site/log/">qedproof.site/log</a>. Base Sepolia is a testnet.</sub>
</p>

## Verdicts and trust levels

| Verdict | Meaning |
|---|---|
| `verified` | the destination shows the claimed outcome, on time |
| `late` | it's there and matches, but appeared after the claimed time plus tolerance |
| `mismatch` | there's an outcome for the target, but a required field differs |
| `failed` | the destination was readable and the outcome wasn't there by the deadline |
| `unverifiable` | the verifier couldn't tell. It's never evidence for or against the agent |

| Level | A checker can confirm | Status in this node |
|---|---|---|
| 1 · Signed | the issuer stated it, and it hasn't been altered | ✅ |
| 2 · Anchored | …and it existed by the anchor time; it can't be backdated or silently deleted | ✅ (EAS on Base) |
| 3 · Attested | …and a specific published verifier build produced it inside a hardware enclave | specified, not built |
| 4 · Web-proven | …and the facts came from the destination's TLS session (zkTLS) | specified, not built |

Full definitions: [`spec/SPEC.md`](spec/SPEC.md) §6–§8.

## What it can check today

| Action | Target | Params | Needs |
|---|---|---|---|
| `github.commit.push` | `owner/repo` | `sha` (40 hex), `branch` | a read-only GitHub token |
| `github.pr.open` | `owner/repo` | `number`, optional `base`, `head_sha` | a read-only GitHub token |
| `github.checks.pass` | `owner/repo` | `sha` | a read-only GitHub token |
| `http.url.status` | an `https://` URL | optional `status` (default 200), `content_fingerprint` | nothing |

Verifiers are plugins in [`node/src/poaw_node/verifiers/`](node/src/poaw_node/verifiers/). New ones are welcome —
see [CONTRIBUTING.md](CONTRIBUTING.md).

## Quickstart (self-host)

**With Docker** (PostgreSQL + the node, on `127.0.0.1:8080`):

```bash
git clone https://github.com/Nuraveda/qed-proof-core.git && cd qed-proof-core
docker compose up -d
docker compose exec node poaw-node create-workspace --name "My team"   # prints an API key ONCE
```

On first start the node creates its receipt-signing key in the `keys` volume. **Back that volume up**: receipts are
verified against that key forever. Change `POSTGRES_PASSWORD` in `docker-compose.yml` before running it anywhere but
your own machine.

**Without Docker** (Python 3.11+, PostgreSQL 14+):

```bash
pip install ./core-python "./node[anchor]"
export POAW_DATABASE_URL=postgresql://user:pass@localhost:5432/poaw
poaw-node init-db                          # applies node/src/poaw_node/schema.sql (safe to re-run)
poaw-node keygen signing.key               # 32-byte Ed25519 seed, mode 600
export POAW_SIGNING_KEY_FILE=$PWD/signing.key
poaw-node create-workspace --name "My team"
poaw-node serve --port 8080                # the API plus a background tick that re-checks queued claims
```

## Send a claim

```bash
curl -X POST http://127.0.0.1:8080/v1/claims \
  -H "Authorization: Bearer <your key>" -H "Content-Type: application/json" \
  -d '{"client_claim_id": "deploy-1", "agent_id": "my-agent", "action": "http.url.status",
       "target": "https://example.com/", "claimed_at": "2026-01-01T00:00:00Z"}'
```

`client_claim_id` is your idempotency key (the same id is the same claim). The response is `202` with a `claim_id`
and, when it was decided straight away, a `receipt_id`. Claims that can't be decided yet are re-checked by the tick
until their deadline.

## Check a receipt yourself

```bash
curl -s http://127.0.0.1:8080/v1/receipts/<receipt_id>      > receipt.json
curl -s http://127.0.0.1:8080/.well-known/poaw-keys.json    > keys.json
uv run spec/tools/check.py receipt.json keys.json --rpc https://sepolia.base.org
```

The checker verifies the signature, the Merkle inclusion proof and (with `--rpc`) the on-chain anchor, and reports
the trust level it could actually confirm. `node/smoke.py` does all of this against a running node in one command.

A hosted receipt page runs the same checks in the reader's browser, with no QED Proof account. This is a real
receipt: the agent claimed a push, GitHub had no such commit, and the receipt still verifies to trust level 2.

<p align="center">
  <a href="https://qedproof.site/r/rcpt_01M3DK4CJD42ZC4HN3BBMKGTW2/"><img src="https://qedproof.site/media/readme-receipt.png" alt="A public receipt page: verdict Failed for a github.commit.push claim, decided failed (not_found), with four checks passed in the browser: signed by the issuer's published key, the claim wasn't altered after signing, included in the append-only log, and the log root anchored on Base Sepolia. Trust level achieved: 2." width="680"></a>
  <br><sub>Open this receipt: <a href="https://qedproof.site/r/rcpt_01M3DK4CJD42ZC4HN3BBMKGTW2/">qedproof.site/r/rcpt_01M3DK4C…GTW2</a></sub>
</p>

## Configuration

Environment variables (full list in [`node/src/poaw_node/selfhost.py`](node/src/poaw_node/selfhost.py)):

| Variable | Required | What |
|---|---|---|
| `POAW_DATABASE_URL` | ✅ | PostgreSQL connection string |
| `POAW_SIGNING_KEY_FILE` | ✅ | the Ed25519 seed that signs receipts (`poaw-node keygen`) |
| `POAW_ISSUER_NAME` | | shown in receipts (default `poaw-node`) |
| `POAW_GITHUB_TOKEN` | | a read-only token for the `github.*` verifiers; without it they return `unverifiable` |
| `POAW_TICK_SECONDS` | | how often queued claims are re-checked (default 30) |
| `POAW_ANCHOR_CHAIN` | | `eip155:84532` (Base Sepolia) or `eip155:8453` (Base) to anchor the log |
| `POAW_ANCHOR_KEY_FILE` | with anchoring | the secp256k1 key that pays for anchors |
| `POAW_ANCHOR_RPC` | | the chain's JSON-RPC URL (default: the public endpoint) |

## Repository layout

```
spec/          the receipt spec (poaw/0.2), JSON Schemas, 35 conformance vectors, the reference checker   Apache-2.0
core-python/   poaw-core: canonical JSON, hashing, signatures, Merkle log primitives                   Apache-2.0
node/          the node: claims API, verifiers, signing, Merkle log, anchoring, CLI, Dockerfile        AGPL-3.0
docker-compose.yml   PostgreSQL + the node
```

## Hosted vs self-hosted

| | Self-hosted (this repo) | Hosted ([qedproof.site](https://qedproof.site)) |
|---|---|---|
| Verification, receipts, log, anchoring | ✅ the same node code | ✅ the same node code |
| Workspaces and API keys | CLI | console, with team members and invites |
| GitHub access | one token you provide | a GitHub App, per workspace, read-only |
| Alerts | stdout log lines | Discord channels, delivery history |
| Signing keys | a key file you hold | cloud KMS |
| Billing, SLAs | — | plans with a free tier |

## Community and support

**Support happens on Discord:** [discord.gg/9yhJs3EdCx](https://discord.gg/9yhJs3EdCx). Open a post in the **#support**
forum (hosted or self-hosted, it's the same place), or join the conversation in #spec and #verifiers. Found a bug in the
code? A GitHub issue is fine too. **Security problems never go on Discord:** use the private reporting below.

## License

Copyright © 2026 **Nuraveda Lab**. See [`NOTICE`](NOTICE).

- `spec/`, `core-python/`: **Apache-2.0** ([`LICENSE-APACHE`](LICENSE-APACHE)). Embed them anywhere.
- `node/`: **AGPL-3.0-only** ([`node/LICENSE`](node/LICENSE)). Run it freely; a modified, hosted version must share its
  changes.

## Contributing

Bug reports, verifiers and spec feedback are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md): commits need a DCO
sign-off, contributions are made under the [CLA](CLA.md), and spec changes need a conformance vector. Everyone taking
part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please report vulnerabilities privately through **Security → Report a vulnerability** on this repository. See
[SECURITY.md](SECURITY.md). Don't open a public issue for a security problem.

---

<div align="center">

Built by the team behind **[QED Proof](https://qedproof.site)** — credit scores for AI agents, built on proof instead of reviews.

</div>
