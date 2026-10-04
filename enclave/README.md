# poaw-enclave

The guest that runs inside an **AWS Nitro Enclave** and produces trust-level-3 observations for Proof of Agent Work
(SPEC §7). It runs the same open verifier and verdict code as the node (`poaw_node.verifiers.REGISTRY`,
`poaw_node.verdict.decide`), then asks the Nitro Security Module (NSM) for an attestation document that binds the
decision to this exact build.

## What runs inside
- `server.py` listens on **vsock port 5005** and answers one request per connection (sequentially).
- `forwarder.py` listens on `127.0.0.1:443` and relays bytes over vsock to the parent (CID 3, port 8443), where the
  host's `vsock-proxy` connects to `api.github.com:443`. `/etc/hosts` maps `api.github.com` to `127.0.0.1`
  (`bootstrap.py`, which also brings loopback up). **TLS is verified inside the enclave** with the image's CA bundle
  (certifi); the host only sees ciphertext.
- `nsm.py` talks to `/dev/nsm` with a ctypes `ioctl` and `cbor2` (pinned). Request CBOR
  `{"Attestation": {"user_data": <32 bytes>, "nonce": null, "public_key": null}}`; response
  `{"Attestation": {"document": <COSE_Sign1>}}` or `{"Error": ...}`. `FakeNsm` is for tests.
- Only actions in `QED_ENCLAVE_ACTIONS` (baked into the image `ENV`, default `github.commit.push`) are served.

## Protocol C4 (host to enclave)
Frames are a 4-byte big-endian length followed by UTF-8 JSON (max 1 MiB). One request, one response.

Request: `{"job_id", "claim": {id, workspace_id, agent_ref, action, target, params, claimed_at, deadline_at,
client_claim_id, claim_digest}, "token": str|null, "attempts": int}` with RFC 3339 UTC times. Unknown or missing keys
are rejected, and the enclave recomputes `claim_digest` from the claim and refuses a mismatch, so it never attests a
claim that is not bound to its digest.

Response: `{"job_id", "outcome": "decided"|"retry"|"error", "verifier": {id, version},
"decision": {verdict, reason, facts, observed_at}|null, "attestation": base64url|null, "error"?: str}`.
- `decided`: attestation present, over the C1 statement computed from this decision.
- `retry`: no final decision yet (the destination may not show the work yet); keep looking.
- `error`: bad request, disallowed action, verifier exception or NSM failure. Never accompanied by an attestation.

The attestation `user_data` is `SHA-256(JCS({claim_digest, verifier{id,version}, observed_at, facts, verdict}))`
(`poaw_core.enclave_statement_digest`).

## PCR0 and `code_hash`
PCR0 is the measurement of the enclave image file (EIF), which contains this code, the pinned Python base and every
dependency. A receipt carries `code_hash = "sha384:" + hex(PCR0)`; a checker verifies the NSM signature chain to the
AWS Nitro root, `pcrs[0] == code_hash` and `user_data == statement digest`, and that `code_hash` is listed in the
issuer's `verifier_builds`. Change one byte of the code or a dependency and PCR0 changes.

## Reproducing a build
1. `docker build --platform linux/arm64 -f oss/enclave/Dockerfile oss/` (context is `oss/`; base image pinned by digest).
2. `nitro-cli build-enclave --docker-uri <image> --output-file qed.eif` prints PCR0/PCR1/PCR2.
3. Compare PCR0 with the `code_hash` in `builds.json`.
Dependencies: `requirements.txt` is generated with
`uv pip compile requirements.in --generate-hashes --python-version 3.12 --python-platform aarch64-unknown-linux-gnu -o requirements.txt`.
Reproducibility is a goal, not a guarantee: `SOURCE_DATE_EPOCH` and timestamp normalisation are set, but byte-identical
EIFs depend on the Docker/nitro-cli versions, so each build publishes its image digest and EIF hash.

## `builds.json`
`{"builds": [{"code_hash": "sha384:<pcr0 hex>", "platform": "aws-nitro-enclave", "version": "<string>",
"source": "<repo url + commit>", "image_digest": "sha256:...", "eif_sha256": "<hex>", "published_at": "<RFC 3339>"}]}`.
Accepting a build is a pull request that appends an entry. Starts empty.

## Honest limits
- Hardware-backed, not unforgeable: the guarantee rests on AWS's Nitro hardware and root key.
- The GitHub installation token is passed in per job by the host, so a malicious host could withhold or replay jobs
  and could lie about the token's scope; it cannot alter what the enclave reads over verified TLS.
- The enclave clock comes from the hypervisor (AWS), not from the enclave itself.
- The attestation proves which code produced the decision, not that the code is bug-free.
- A `retry` or `error` is not attested; the host can only delay a verdict, never forge one.

## Tests
`cd oss/enclave && uv run --extra test pytest -q`
