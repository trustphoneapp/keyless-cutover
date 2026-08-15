# Independent reviewer and K0 operator runbook

This runbook is the human gate for the live Keyless K0 transaction. It does not authorize anyone to share a browser authorization code, private key, GitHub secret, access token, ID token, or application token. Keyless never needs those values in chat, a pull-request comment, or an evidence artifact.

## Historical stop state before the reviewed ProofV2 milestone — superseded

- `release/live-agent-v2` was the cumulative non-cutover release candidate in PR #11.
- `keyless/k0-live` was the compiler-produced WIF cutover in draft PR #3.
- `KEYLESS_K0_ENABLED` was `false`.
- The exact legacy service-account key remained enabled.
- At that checkpoint H2 was proven while H1 and H3–H8 were incomplete.
- At that checkpoint no reviewer other than the repository owner had qualifying authority.

Those historical conditions are superseded. PR #3 is merged, `KEYLESS_K0_ENABLED` is `true`, `wif-1` is live, reviewed ProofV2 passed, deterministic collectors prove H1–H8 with the forbidden revision unchanged, and the exact key is now disabled with matching human Admin Activity. That transaction is nevertheless terminal historical readiness evidence: no canonical v3 pre-disable archive checkpoint was reviewed and merged before disable. Do not continue it, do not run its missing post-disable steps, and never re-enable its key to try to make it pass. A v3 result requires the separately authorized fresh disposable transaction below.

## Required independent GitHub reviewer

Use one GitHub account whose numeric user ID differs from actor/owner ID `289479481`. The person must:

1. accept write access to `trustphoneapp/keyless-cutover` so GitHub counts the review;
2. review from their own account, not a shared session;
3. be the required reviewer for the `production` environment with prevent-self-review enabled;
4. own the separate H1 repository, so its numeric owner ID is genuinely different.

Grant only the permissions required for those GitHub duties. Do not grant the GitHub reviewer project Owner, IAM Admin, service-account Token Creator, repository secrets access, or runtime-agent mutation authority.

## Separate human GCP key operator

The key operator is a separately authenticated human boundary from the Keyless runtime and may be distinct from the independent GitHub reviewer. The operator receives a fresh exact-key approval only after the canonical archive-checkpoint PR is merged and reread, disables—not deletes—the exact fresh key, and appears as the human principal in Admin Activity. The Keyless runtime cannot hold or use this identity. If delegated, scope `roles/iam.serviceAccountKeyAdmin` to the exact disposable deployment service account only. The actor recorded in the historical receipt is evidence of that old event, not authority for the fresh transaction.

## Authority setup

The project owner records the reviewer's GitHub login and numeric GitHub user ID, plus the separate key operator's GCP principal. Before continuing, independently read back:

- repository collaborator permission is `write`;
- `main` still requires CI, one approval, last-pusher approval, stale-review dismissal, and linear history;
- `production` requires the independent reviewer, prevents self-review, and allows protected branches only; and
- the GCP key operator is an explicit human identity outside the Keyless runtime and has disable plus rollback authority for the exact deployment key.

If any read-back is ambiguous, stop. Never work around a missing reviewer by weakening branch or environment protection.

## Fresh ProofV2 operator mechanics

The operator uses two separate commands so issuance cannot silently dispatch a workflow and verification cannot silently create a challenge. `issue` performs exactly one Firestore document creation and prints only the five bounded workflow inputs. `verify` is read-only in GitHub and Google IAM until the signed proof, exact completed run, workflow blob, and independent environment approval all agree; only then does it atomically transition the same challenge from `ISSUED` to `CONSUMED` and prove a second consume is rejected.

The historical command values below must not be reused. For the fresh transaction, substitute only identifiers derived from its separately reviewed plan; never copy a historical challenge, run, project, key, or receipt.

1. Reconfirm `main`, CI, required linear history, the production reviewer, exact fresh active user-managed key, repository/owner IDs, and five-minute operator scope.
2. With explicit Firestore-write permission, run the issue command once. Do not issue early: expiry is exactly five minutes.

   ```sh
   npm run proofv2 -- issue \
     --project-id keyless-k0-20260813 \
     --migration-id k0-proofv2-reviewed \
     --owner-id 289479481 \
     --repository-id 1332803088 \
     --workflow-path .github/workflows/k0-proof-v2.yml \
     --client-email keyless-deploy@keyless-k0-20260813.iam.gserviceaccount.com
   ```

3. With separate workflow-dispatch permission, dispatch `k0-proof-v2.yml` using exactly the five printed values and `ref=main`.
4. `cherala2002` opens the pending run and selects **Review deployments → production → Approve and deploy**. GitHub does not expose the environment secret to the job before this approval.
5. After completion, set `KEYLESS_GITHUB_TOKEN` from a bounded read-capable GitHub token and run the verify command. Never pass a token on the command line.

   ```sh
   export KEYLESS_GITHUB_TOKEN="$(gh auth token)"
   npm run proofv2 -- verify \
     --project-id keyless-k0-20260813 \
     --owner trustphoneapp \
     --repository keyless-cutover \
     --run-id RUN_ID_FROM_GITHUB \
     --workflow-path .github/workflows/k0-proof-v2.yml
   unset KEYLESS_GITHUB_TOKEN
   ```
6. Preserve the credential-free receipt and GitHub run/artifact/environment-review identifiers. Re-query Firestore and Google IAM independently.

Stop on expiry, multiple matching artifacts, absent/self approval, wrong workflow/ref/run, disabled or mismatched key, certificate failure, Firestore contention, accepted replay, or any credential-shaped artifact. Never re-dispatch an expired challenge and never create a replacement challenge without a new explicit write permission.

## Protected RC and fresh transaction setup

### 1. Protected release candidate

Completed. PR #18 published the fail-closed K0 evidence pipeline and PR #19 replaced the canonical workflow with the inactive legacy-baseline template. Independent review by `cherala2002` applied to each exact head before merge. Required `test` was green.

Live read-back at `2026-08-15T06:02:22Z` confirmed CI strictness, one approval, stale-review dismissal, last-push approval, admin enforcement, and `required_linear_history: true`. The `production` environment still requires `cherala2002`, prevents self-review, and allows protected branches only. Credential-free record: `docs/evidence/REPOSITORY_PROTECTION_2026-08-15.md`.

Stop before any fresh transaction action if a later read-back differs.

### 2. Fresh disposable transaction

Create a separately authorized disposable key transaction after the protected RC and branch-protection read-back. Use a fresh key, challenge, runs, release markers, approvals, and observations; never copy the historical transaction into a new manifest. Re-run the exact compiler, provider/IAM parity, and downstream no-widening checks. Keyless never auto-merges, applies IAM, or disables a key.

## H1 foreign-owner probe

The independent person creates a disposable repository under their own GitHub account. A repository under `trustphoneapp`, even with a different repository ID, is H2 and cannot satisfy H1.

Use `k0/templates/k0-external-hostile.yml` byte-for-byte at `.github/workflows/k0-deploy.yml`. Configure only the documented non-secret repository variables for project, provider, service account, and canonical audience; add `demo/release.txt`; create a `production` environment; and push to protected `main`. Do not add a Google key or any other secret.

H1 passes only when the independent collector verifies all of the following:

- the run's numeric owner ID differs from `289479481`;
- Google auth reached STS/WIF and was rejected by the provider condition;
- the bounded client artifact and refetched GitHub run/log agree; and
- the forbidden Cloud Run revision is unchanged.

A workflow syntax error, missing environment approval, network failure, or failure before STS is `NOT RUN`, never a denial.

## Live K0 order

1. Merge the protected RC, repair `required_linear_history: true`, and independently read back the complete branch and environment protection tuple. **Done** at `2026-08-15T06:02:22Z`; see `docs/evidence/REPOSITORY_PROTECTION_2026-08-15.md`.
2. Under separate authorization, create the fresh disposable key transaction and collect its successful legacy baseline.
3. Run fresh ProofV2, deploy/read back `wif-1`, prove exact provider/IAM parity, and execute H1–H8 including a real H2 at their documented controls; verify the forbidden service remains unchanged.
4. Build the canonical pre-disable archive, commit it through a protected PR, obtain independent review of its exact head, merge it, and read back the exact archive bytes while the fresh key is still enabled. Any missing source stops the transaction.
5. Show the human key operator the exact fresh service account, key ID, archive digest, and rollback window. The operator disables—never deletes—the exact key; independently read back `disabled: true` and one matching `DisableServiceAccountKey` Admin Activity entry.
6. On a new hosted runner, execute the non-deploying legacy-auth probe. It must make a fresh Google request and receive a recognized disabled/invalid-key rejection. Complete this denial before WIF-2.
7. Only after legacy denial, deploy `wif-2` on another new hosted runner and read back the exact allowed revision, WIF audit, parity, and unchanged forbidden revision.
8. Run the local authenticated read-only pending issuer against those exact sources. Verify its private canonical output; status remains `K0_VERIFIED_RECEIPT_PENDING`, authorization `RECOLLECTION_REQUIRED`, and `release_ready: false`.
9. Through separate authorization, obtain the scoped real KMS signature and verify it against pinned out-of-band public trust. The signature changes no release state.
10. A separate human reviews the complete evidence and owns any release decision outside the local state machine.

The immediate result may claim only: **the key is disabled, fresh key authentication is rejected, and fresh WIF authentication succeeds**. It must not claim that access tokens minted before disable were revoked.

## Rollback and kill rules

- Before key disable: revert the reviewed workflow or remove only the migration-owned WIF binding/provider after a new human review.
- Historical disabled key: never re-enable it; its transaction remains historical readiness only.
- Fresh transaction after key disable: Keyless cannot re-enable the key. A human rollback may re-enable the fresh key and revert the workflow only to restore service; doing so kills that transaction and requires another fresh one.
- Never delete the key during K0.
- Stop and preserve evidence on unexpected hostile success, privilege widening, target mutation, key ambiguity, source drift, missing independent approval, secret exposure, or failed post-disable WIF deployment.
- A stopped or failed K0 remains `NO-GO`; do not repair the evidence manually or relabel it as a pass.

## Handoff data

To begin this runbook, the project owner needs only the independent person's GitHub username and the GCP identity they choose for the narrowly scoped key-operator role. Authorization codes and credentials are never handoff data.
