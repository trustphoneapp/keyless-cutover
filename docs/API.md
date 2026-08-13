# Internal API and event contracts

> Historical broad-control-plane design. The hackathon API is not yet implemented and must follow `MASTER_PLAN.md` plus ADR 0002; Tasks, webhooks, and autonomous IAM are out of v1.

This is the v1 contract outline. Exact OpenAPI/JSON Schemas are implemented in K1.

## Public service

### `POST /webhooks/github`

Verifies the raw-body GitHub HMAC, records the delivery ID/body digest, enqueues reconciliation, and returns quickly. Replayed ID + same digest is idempotent; same ID + different digest is a security error.

### `POST /migrations`

Creates a migration for one selected repository, workflow path, GCP project number, deploy service account, key resource, Cloud Run service, and region. Creation is rejected unless the caller is authorized for the installed repository and selected project.

### `GET /migrations/{id}`

Returns current state, revision, evidence labels, holds, and allowed human actions. It never returns credentials or raw tokens.

### `POST /migrations/{id}/approvals/apply`

Accepts an approval bound to the exact plan digest and expiry. The server recomputes the digest from canonical stored inputs.

### `POST /migrations/{id}/observe-key-disable`

Does not disable a key. It requests an authoritative re-observation after the human action.

### `GET /receipts/{id}`

Returns canonical receipt JSON, signature, KMS public-key metadata, and verification instructions.

## Worker task

`POST /tasks/reconcile` is callable only by the Cloud Tasks identity. Payload contains migration ID, expected revision, and operation key. Payload data is a wakeup; worker loads canonical Firestore state and re-observes external systems.

## Typed model contracts

### `EvidenceBundle`

- immutable repository/owner IDs;
- selected workflow/script AST facts;
- secret reference metadata;
- key-proof status;
- normalized GCP/IAM/WIF/Cloud Run facts;
- redacted failure evidence;
- evidence provenance labels.

### `MigrationIntent`

- detected authentication mechanism;
- selected service account/key/project/target;
- required workflow semantic changes;
- diagnosis/explanation;
- uncertainties and missing evidence;
- no raw CEL, shell command, IAM policy, or mutation tool invocation.

### `DeterministicPlan`

Compiled by trusted code from observed facts and allowlisted intent:

- exact WIF mapping/condition/audience;
- exact IAM member/role/resource;
- exact preserving workflow patch;
- normalized permission diff;
- hostile-test matrix;
- approval digest.

## Error model

Use stable classes: `UNSUPPORTED`, `MISSING_EVIDENCE`, `STALE_APPROVAL`, `DRIFT_CONFLICT`, `SECURITY_ASSERTION_FAILED`, `TRANSIENT`, `PROPAGATION_PENDING`, `AMBIGUOUS_COMMIT`, `AUTHORIZATION`, `CANCELLED`, and `ROLLBACK_REQUIRES_HUMAN`.

Errors expose remediation without embedding secrets or uncontrolled log content.
