# State machine and failure recovery

> Historical full-control-plane model. Hackathon v1 uses the evidence-derived phases in `ARCHITECTURE.md`; Firestore exists for challenge replay and minimal state, not Tasks/outbox orchestration.

## Canonical states

```text
NEW
→ OBSERVED
→ KEY_PROVED
→ PLAN_VALIDATED
→ PR_OPEN
→ PR_REVIEWED
→ APPLY_APPROVED
→ WIF_APPLIED
→ PR_MERGED
→ PRE_DISABLE_CANARY_PASSED
→ EIGHT_DENIALS_PASSED
→ READY_FOR_HUMAN_DISABLE
→ KEY_DISABLED_OBSERVED
→ POST_DISABLE_CANARY_PASSED
→ LEGACY_REAUTH_DENIED
→ RECEIPT_ISSUED
```

Side states:

- `HOLD_MISSING_EVIDENCE`
- `HOLD_UNSUPPORTED`
- `HOLD_DRIFT`
- `HOLD_EXTERNAL_FAILURE`
- `FAILED_SAFE`
- `ABORTED`
- `ROLLBACK_REQUIRED`

## Transition invariants

| Transition | Required facts |
|---|---|
| `NEW → OBSERVED` | Exact repo/owner IDs, workflow blob SHA, target project/service account/key inventory, branch/environment rules, and IAM policy etag captured |
| `OBSERVED → KEY_PROVED` | Signed nonce probe verifies against the exact GCP public key; no raw private material leaves runner |
| `KEY_PROVED → PLAN_VALIDATED` | Typed IR complete; policy compiler passes; no privilege widening; support gate passes |
| `PLAN_VALIDATED → PR_OPEN` | Current repo head and IAM etag equal plan preconditions; branch/PR are Keyless-owned and idempotent |
| `PR_OPEN → PR_REVIEWED` | Independent review applies to exact head SHA; stale approvals dismissed |
| `PR_REVIEWED → APPLY_APPROVED` | Separate Keyless change-control approval binds the plan digest and IAM preimage; the GitHub Environment later gates deployment |
| `APPLY_APPROVED → WIF_APPLIED` | Fresh provider/binding read back exactly; no unrelated IAM overwrite |
| `WIF_APPLIED → PR_MERGED` | Human merge; merged tree exactly contains approved patch |
| `PR_MERGED → PRE_DISABLE_CANARY_PASSED` | Exact merged SHA deploys `wif-1` through observed federated identity |
| `PRE_DISABLE_CANARY_PASSED → EIGHT_DENIALS_PASSED` | All eight real negative cases reject at expected layer; no protected mutation |
| `EIGHT_DENIALS_PASSED → READY_FOR_HUMAN_DISABLE` | Plan, commit, provider, IAM, key state, and canary freshness revalidated |
| `READY_FOR_HUMAN_DISABLE → KEY_DISABLED_OBSERVED` | Human disables exact key; fresh API GET observes `DISABLED` |
| `KEY_DISABLED_OBSERVED → POST_DISABLE_CANARY_PASSED` | New GitHub job deploys `wif-2` with observed WIF principal |
| `POST_DISABLE_CANARY_PASSED → LEGACY_REAUTH_DENIED` | New authentication attempt using the disabled key fails; no pre-minted token reused |
| `LEGACY_REAUTH_DENIED → RECEIPT_ISSUED` | Evidence manifest complete; KMS signature generated; limitations embedded |

## Approval invalidation

The approval digest binds:

- Repository and owner numeric IDs.
- Base/head SHA, workflow path, and blob hash.
- Secret name.
- Probe nonce, key ID, service-account email, and signature evidence.
- GCP project number, key state, Cloud Run target, and runtime identity.
- WIF provider configuration.
- IAM etag and normalized policy hash.
- Policy bundle, model, and prompt-template versions.

Any change invalidates approval and returns to `HOLD_DRIFT`.

## Firestore structure

```text
/targets/{sha256(repoId:keyId)}
/migrations/{migrationId}
/migrations/{migrationId}/plans/{version}
/migrations/{migrationId}/approvals/{approvalId}
/migrations/{migrationId}/operations/{operationKey}
/migrations/{migrationId}/events/{eventId}
/migrations/{migrationId}/evidence/{evidenceId}
/webhookDeliveries/{deliveryId}
/outbox/{operationStepHash}
/receipts/{migrationId}:{version}
```

The migration document is current-state truth. Events and evidence are append-only audit material, not a separate event-sourcing implementation.

## Delivery semantics

- Cloud Tasks is at-least-once.
- GitHub webhooks may be duplicated, delayed, missed, or out of order.
- A webhook/task only wakes reconciliation; it never asserts truth.
- Each worker refetches GitHub/GCP state and checks the migration version before advancing.
- Deterministic task IDs reduce duplicates, but idempotent handlers remain mandatory.
- A periodic reconciler repairs missed deliveries and stuck outbox entries.

## Crash matrix

| Crash point | Recovery |
|---|---|
| Before intent | No external call exists |
| Intent stored, before call | Observe then apply if still valid |
| Timeout during call | Mark ambiguous; observe target before any retry |
| External success, before persistence | Deterministic resource/branch/PR/key state recovers result |
| Evidence stored, before transition | Versioned transaction advances once |
| State and outbox stored, before task creation | Sweeper publishes task |
| Task created, before published flag | Same task ID returns already-exists; mark scheduled |

## IAM concurrency

- Read policy version 3 with etag.
- Store normalized semantic policy hash.
- Apply with etag precondition.
- A 409/ABORTED caused by live drift invalidates approval; do not silently rebase.
- Compensation removes only an exact Keyless-created binding/provider and only when ownership and current etag still match.

## Propagation and evidence delay

- Poll with bounded exponential backoff; never use fixed long sleeps.
- WIF/IAM propagation timeout becomes `HOLD_EXTERNAL_FAILURE`, not a weaker trust condition.
- Delayed audit evidence leaves the receipt pending.
- Absence of a log is never proof of denial.

## Cancellation and rollback

- Before WIF mutation: clean abort.
- After additive WIF mutation but before merge: reviewed compensation may remove only Keyless-owned resources.
- After merge but before key disable: create a reviewed revert PR; keep key enabled.
- After key disable: Keyless never re-enables. Human follows rollback instructions and explicitly re-enables the exact key if required.
- Key deletion is never part of Keyless.
