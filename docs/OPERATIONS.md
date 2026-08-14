# Operations and failure recovery

> Historical future design. The hackathon build makes no webhook, Cloud Tasks, outbox, exactly-once, or autonomous crash-recovery guarantee.

## Reconciliation rule

Webhooks and Cloud Tasks are wakeups, not truth. Every worker re-fetches authoritative GitHub/GCP state before transitioning.

Every external mutation follows:

`persist intent → observe → validate approval/preconditions → apply once → observe again → store evidence → transition`

If a call times out, mark it ambiguous and observe the target. Never retry a mutation blindly.

## Scheduled reconciliation

- Sweep active migrations every one to two minutes.
- Recover unpublished transactional-outbox records.
- Create Cloud Tasks with deterministic IDs.
- Treat `AlreadyExists` as scheduled.
- Use bounded exponential backoff with jitter for 429, 5xx, and network failures.
- Do not retry security assertion failures, unsupported input, stale approval, or ordinary 4xx configuration failures.

## Webhooks

- Verify `X-Hub-Signature-256` against the raw body before parsing.
- Dedupe on `X-GitHub-Delivery`; same ID with a different digest is a security error.
- Store only minimized, redacted payload data with short retention.
- Return quickly and process asynchronously.
- A late event can only wake reconciliation; it cannot reverse externally observed state.

## Concurrency

- One active migration per immutable repository ID + key ID.
- Firestore revision/CAS protects state; a lease is only a liveness mechanism.
- IAM writes use version 3 and `etag`.
- PR branches use deterministic `keyless/{migrationId}` names and never force-push.
- Workflow runs carry migration ID, plan digest, and exact head SHA; only exact matches count.

## Propagation

Do not use fixed sleeps. Poll positive probes with bounded backoff because IAM/WIF changes may require minutes to propagate. A timeout enters `PROPAGATION_PENDING` or `HOLD`; it never causes Keyless to weaken a condition.

Audit logs can also be delayed. A receipt may remain provisional while evidence is pending.

## Monitoring

Alert on:

- unexpected hostile-path success;
- secret/leak detector finding;
- stale approval at mutation boundary;
- IAM/provider drift;
- key-disabled state with failed WIF continuity;
- compensation blocked by third-party change;
- repeated task failures or stuck migration lease;
- receipt signature/verification failure.

## Incident classes

| Class | Response |
|---|---|
| Transient API/network | Backoff and retry after observation. |
| Propagation/evidence pending | Schedule bounded poll; preserve state. |
| Ambiguous commit | Observe target before another call. |
| Drift conflict | Invalidate approval and enter `HOLD`. |
| Security assertion failed | Enter `FAILED_SAFE`; preserve and isolate only owned trust when safe. |
| Missing permission/config | Stop for operator correction; avoid retry storm. |
| Unsupported input | Refuse without mutation. |
| Cancellation after disable | Require human rollback decision. |

## Backup and retention

- Firestore current state is canonical; events/evidence are append-only history.
- Evidence objects are immutable by generation and hashed into receipts.
- Keep no private key, GitHub secret value, GitHub OIDC token, Google access token, or generated credentials file.
- Retention periods must be documented before accepting non-demo data; the hackathon environment uses disposable repositories/projects and explicit teardown.

## Teardown

After the observation window and demo:

1. Export the authentically issued exact pending receipt, its scoped signature sidecar, and evidence manifest without relabeling them as release authorization.
2. Human removes the obsolete GitHub secret.
3. Human decides whether to delete the disabled GCP key.
4. Remove disposable repositories/projects through their owning consoles.
5. Rotate/delete the GitHub App private key and webhook secret for the demo installation.

Keyless itself never performs broad teardown or recursive cleanup.
