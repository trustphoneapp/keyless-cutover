# State machine and failure recovery

> Current fail-closed release sequence. Firestore remains limited to challenge replay and minimal state; the later Tasks/outbox sections are preserved as historical design only.

The already-disabled August transaction is terminal `HISTORICAL_READINESS_ONLY`: it has no canonical v3 pre-disable archive checkpoint completed before disable. It cannot advance, must not be repaired by re-enabling its key, and supplies readiness context only. The sequence below applies to a separately authorized fresh disposable key transaction.

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
→ PRE_DISABLE_ARCHIVE_CHECKPOINTED
→ READY_FOR_HUMAN_DISABLE
→ KEY_DISABLED_OBSERVED
→ LEGACY_REAUTH_DENIED
→ POST_DISABLE_CANARY_PASSED
→ AUTHENTICATED_PENDING_OUTPUT_VERIFIED
→ KMS_SIGNATURE_VERIFIED
→ AWAITING_HUMAN_RELEASE
```

Side states:

- `HOLD_MISSING_EVIDENCE`
- `HOLD_UNSUPPORTED`
- `HOLD_DRIFT`
- `HOLD_EXTERNAL_FAILURE`
- `FAILED_SAFE`
- `ABORTED`
- `ROLLBACK_REQUIRED`
- `HISTORICAL_READINESS_ONLY`

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
| `PRE_DISABLE_CANARY_PASSED → EIGHT_DENIALS_PASSED` | All eight fresh negative cases, including H2, reject at their expected layer; no protected mutation |
| `EIGHT_DENIALS_PASSED → PRE_DISABLE_ARCHIVE_CHECKPOINTED` | Fresh legacy baseline, ProofV2, WIF-1 parity, H1–H8, and forbidden-target observations are sealed in the canonical archive; its protected PR is independently reviewed and merged while the key remains enabled |
| `PRE_DISABLE_ARCHIVE_CHECKPOINTED → READY_FOR_HUMAN_DISABLE` | Exact merged archive bytes, plan, provider, IAM, key state, protection, and canary freshness are revalidated |
| `READY_FOR_HUMAN_DISABLE → KEY_DISABLED_OBSERVED` | Human disables exact key; fresh API GET observes `DISABLED` |
| `KEY_DISABLED_OBSERVED → LEGACY_REAUTH_DENIED` | New hosted authentication attempt using the disabled key reaches Google and fails; no pre-minted token is reused |
| `LEGACY_REAUTH_DENIED → POST_DISABLE_CANARY_PASSED` | Only after legacy denial, a new GitHub job deploys and reads back `wif-2` with observed WIF identity |
| `POST_DISABLE_CANARY_PASSED → AUTHENTICATED_PENDING_OUTPUT_VERIFIED` | The local read-only issuer authentically recollects every final source, verifies v3, and writes its exact private pending output; authorization remains `RECOLLECTION_REQUIRED` |
| `AUTHENTICATED_PENDING_OUTPUT_VERIFIED → KMS_SIGNATURE_VERIFIED` | A separately authorized scoped KMS operation signs the exact pending-receipt digest and pinned public verification succeeds; no release state changes |
| `KMS_SIGNATURE_VERIFIED → AWAITING_HUMAN_RELEASE` | Deterministic processing stops with `release_ready: false`; a separate human reviews the evidence and owns any release decision outside local state |

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
- Historical already-disabled key: never re-enable it; preserve the transaction as readiness evidence only.
- Fresh transaction after key disable: Keyless never re-enables. A separately authorized human may roll back the fresh key/workflow only to restore service, which kills that transaction rather than allowing it to resume.
- Key deletion is never part of Keyless.
