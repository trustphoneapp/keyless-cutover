# Approvals, cancellation, and rollback

> ADR 0002 governs: humans apply IAM, merge the PR, and disable/re-enable keys. Any automated-IAM language below is post-hackathon historical design.

## Two independent approvals

### Approval A — additive cutover plan

Authorizes only:

- creation of the named Keyless-owned WIF provider;
- addition of the exact service-account impersonation binding;
- creation of the exact GitHub PR patch.

It is bound to repository and owner IDs, base/head SHA, workflow hash, patch hash, WIF condition and audience, IAM preimage/etag, permission diff, provider ID, selected service account, and an expiry.

### Approval B — human key disable

This is a fresh approval after the merged WIF workflow and denial suite pass. It is bound to the exact key resource ID, merged commit, successful WIF run, current IAM/provider hashes, denial result digest, and current key-enabled observation.

Keyless does not perform this action. The authorized human runs the disable operation and Keyless independently observes its result.

## Approval invalidation

An approval becomes stale after any:

- PR push, base update, force-push, or workflow change;
- repository rename/transfer that changes the trust representation;
- branch rule or environment protection change;
- WIF provider/audience/condition change;
- IAM policy change or `etag` mismatch;
- service-account/key state change;
- expiration or approver revocation.

Stale approval always moves the migration to `HOLD`; it never auto-rebases.

## Cancellation matrix

| Point | Safe response |
|---|---|
| Before provisioning | Mark cancelled; no external residue. |
| Provider/binding created, PR not merged | Remove only Keyless-created resources if the original approval explicitly covers compensation and live state still matches. Otherwise report residue. |
| PR merged, old key enabled | Propose a human-reviewed rollback PR. Do not disable the provider automatically because that may cause an outage. |
| Old key disabled | Stop. Human decides whether to re-enable the exact key and revert the workflow. Keyless never auto-enables it. |

## Rollback truth

- Disable, do not delete, during the demonstration and observation window.
- A disabled key can be re-enabled by an authorized human; a deleted key cannot be recovered.
- Disabling a key blocks new authentication but does not invalidate access tokens minted earlier.
- Removing or disabling a WIF provider also does not revoke credentials already issued.
- The immediate receipt can prove a new old-key authentication attempt fails and a new WIF attempt succeeds. It cannot prove that every previously issued credential has expired.

## Failure runbooks

### IAM `409 ABORTED`

Freeze, fetch policy version 3, compare semantic drift, and request a new plan/approval. Never overwrite a concurrent administrator change.

### Authorized WIF path still denied

Inspect the actual GitHub claims, audience, mapping, condition, service-account binding, enabled APIs, and bounded propagation. Never broaden the trust condition to make the demo pass.

### Hostile identity unexpectedly succeeds

Enter `FAILED_SAFE`. If concurrency guards prove the provider/binding is solely Keyless-owned and unchanged, isolate that path; otherwise stop and give the human exact cleanup instructions. Preserve all evidence. Do not disable the old key.

### Key observed disabled but WIF deployment fails

Enter `ROLLBACK_REQUIRES_HUMAN`. Offer the exact re-enable and workflow-revert plan; do not perform either action automatically.

### Audit evidence is delayed or absent

Keep the receipt provisional. Never interpret absence as proof of denial or non-use.
