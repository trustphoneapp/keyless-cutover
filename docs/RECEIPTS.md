# Verifiable receipt

> KMS receipt work begins only after K0. A signature proves origin/integrity, not external facts; `PROVISIONAL/evidence_pending` and `FINAL/verified_cutover` are distinct.

## Purpose

The receipt is an independently checkable account of what Keyless observed, proposed, changed, tested, and did not prove. It is not a compliance certificate.

## Format

1. K0 produces a version-2 evidence manifest. Every claim references one or more `E###` ledger entries containing an allowlisted source kind, bounded locator, observation time, SHA-256 artifact digest, and optional HTTPS inspection URL.
2. The K0 verifier requires the correct evidence kinds for ProofV2, WIF readback, H1–H8, key disable, fresh legacy denial, post-disable continuity, and leak scan. Every evidence entry must be referenced.
3. After K0 passes, create canonical receipt JSON from that verified manifest plus K1 agent/PR evidence.
4. Hash it with SHA-256 and sign the digest using an asymmetric Cloud KMS key.
5. Store the JSON, signature, public-key version, and evidence hashes.
6. Publish the receipt ID and digest in a GitHub Check or PR comment as an external anchor.

The repository currently includes the K0 v2 manifest verifier. The KMS receipt signer/verifier is intentionally not implemented until K0 passes. When implemented, changing one byte must fail verification.

## Required fields

### Identity

- migration and receipt IDs;
- schema version and issuance time;
- immutable GitHub owner/repository IDs and display names;
- GCP project number, service account, key resource ID, provider resource name;
- Cloud Run service and region.

### Source and change

- base, PR head, and merged commit SHA;
- workflow path and content hashes before/after;
- typed plan digest;
- IAM version-3 pre/post policy hashes and etags;
- normalized permission diff;
- WIF mapping, condition, and audience hashes.

### Key proof

- probe nonce and domain version;
- GitHub run ID/attempt/head SHA;
- reported client email and private-key ID;
- signed probe payload hash;
- public-key verification result;
- no private key or GitHub secret value.

### Verification

- legacy baseline run and `legacy-1` revision;
- pre-disable WIF run and `wif-1` revision;
- every denial case, expected rejection point, actual conclusion, and unchanged forbidden target evidence;
- human key-disable actor reference and observed key status;
- fresh post-disable WIF run and `wif-2` revision;
- fresh legacy-key authentication failure;
- available STS, IAM Credentials, Cloud Run, IAM Admin Activity, and target API audit identifiers.

### Limitations

- audit evidence still pending;
- unsupported claims or systems not tested;
- key disable does not revoke previously minted tokens;
- key was disabled, not deleted;
- receipt is scoped to the named workflow, identities, service account, service, and test time.

## Evidence labels

Every assertion is labeled:

- `OBSERVED`: fetched from GitHub/GCP or cryptographically verified.
- `DETERMINISTICALLY_DERIVED`: exact code computed it from observed inputs.
- `GEMINI_SUGGESTED`: model interpretation awaiting a deterministic or human gate.
- `MISSING`: required evidence absent; blocks receipt completion.

## What is not proof

- A screenshot without retrievable identifiers.
- An HTTP 2xx without read-after-write verification.
- A missing audit log.
- A denied step that never reached the intended security control.
- An LLM judgment that access is safe.
- A cached token succeeding or failing after key disable.
- A database row written only by Keyless without external corroboration.
