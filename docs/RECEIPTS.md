# Verifiable receipt

> Local code constructs only a deterministic pending receipt. A signature proves origin/integrity, not external facts, and never authorizes release without authenticated live recollection and issuance.

## Purpose

The receipt is an independently checkable account of what Keyless observed, proposed, changed, tested, and did not prove. It is not a compliance certificate.

## Format

1. K0 v3 includes authenticated GitHub workflow-approval/deploy collectors and bounded GCP provider, WIF-audit, key-disable, and Cloud Run readback collectors. Every claim references one or more `E###` ledger entries containing an allowlisted source kind, bounded locator, observation time, SHA-256 artifact digest, and optional HTTPS inspection URL. The offline assembler validates supplied bytes and semantics but cannot by itself prove that those collectors produced them.
2. Each ledger entry resolves to exact canonical `artifacts/E###.json` bytes. The verifier requires exact envelope/manifest agreement, bounded regular files, a clean credential scan, recomputed digests, exact directory enumeration, and no missing, duplicate, or unreferenced artifact.
3. Semantic verification binds exact ProofV2 and reviewed GitHub run/workflow context, WIF provider/audit identity, authoritative Cloud Run revision/release/image state, H1–H8 enforcement points and bracketing unchanged-target observations, human disable state/audit identity, fresh legacy denial, post-disable `wif-2`, scope consistency, and event ordering. For the 48-hour maximum, it selects the earliest authoritative occurrence time, checkpoint-receipt `recorded_at`, or checkpoint event time across the final evidence and requires `manifest.assembled_at`—the latest authenticated final collection—to be no more than 48 hours later. Archive or checkpoint sealing and later recollection cannot reset, backdate, or extend that window.
4. The shared offline loader captures canonical `manifest.json` and every artifact buffer once. The deterministic pending receipt binds those exact manifest bytes, their SHA-256 digest, ordered evidence digests, v3 scope/results/limitations, and `manifest.assembled_at`; rebuilding it is byte-identical.
5. The only implemented receipt state is `K0_VERIFIED_RECEIPT_PENDING` with `authorization: RECOLLECTION_REQUIRED` and `release_ready: false`. Its raw bytes must themselves be canonical; whitespace, an extra trailing newline, reordered keys, truncation, or one changed byte fails.
6. Production code can create an inert, domain-separated SHA-256 KMS digest request for one pinned full key version and can verify a canonical signature sidecar using the exact pending-receipt bytes, approved RSA algorithm, and out-of-band pinned public key.
7. The published RC includes a fixed authenticated read-only recollection and pending-issuance path. It exists, is tested, and is merged, but it has not been executed against an eligible live transaction. It requires an exact reviewed/merged checkpoint archive created while a fresh disposable transaction's key remains enabled, a GitHub read token from the environment, read-only GCP ADC, and the unchanged 48-hour calculation in item 3. The already-disabled historical transaction has no such checkpoint, cannot satisfy v3, and must never be resumed by re-enabling its key. The filesafe CLI writes one canonical private JSON basename in the current working directory and re-verifies it through the atomically reserved handle.
8. Production code still has no signer, private-key parameter, KMS client/call, signing command, or release fallback. A valid signature alone never changes authorization or release readiness; publishing an external anchor remains a later live gate.

The deterministic mutation matrix currently rejects all 36/36 named bundle, artifact, receipt, signature, and trust-anchor mutations, including one-byte and noncanonical-byte changes, mixed or mismatched manifest/artifact snapshots, wrong digest/algorithm/key version/public key, and a valid second-key signature substituted against the pinned trust anchor. These are local false-safe controls, not a claim that a scoped live KMS signature exists.

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
- exact successful `DisableServiceAccountKey` Admin Activity insert ID, resource, principal, and timestamp within the approved window;
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
