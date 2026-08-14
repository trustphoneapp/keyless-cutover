# Independent reviewer and K0 operator runbook

This runbook is the human gate for the live Keyless K0 transaction. It does not authorize anyone to share a browser authorization code, private key, GitHub secret, access token, ID token, or application token. Keyless never needs those values in chat, a pull-request comment, or an evidence artifact.

## Historical stop state before the reviewed ProofV2 milestone — superseded

- `release/live-agent-v2` was the cumulative non-cutover release candidate in PR #11.
- `keyless/k0-live` was the compiler-produced WIF cutover in draft PR #3.
- `KEYLESS_K0_ENABLED` was `false`.
- The exact legacy service-account key remained enabled.
- At that checkpoint H2 was proven while H1 and H3–H8 were incomplete.
- At that checkpoint no reviewer other than the repository owner had qualifying authority.

Those historical conditions are superseded. PR #3 is merged, `KEYLESS_K0_ENABLED` is `true`, `wif-1` is live, reviewed ProofV2 passed, deterministic collectors prove H1–H8 with the forbidden revision unchanged, and the exact key is now disabled with matching human Admin Activity. Continue only from the fresh legacy-auth probe and post-disable WIF steps below; do not repeat the completed pre-disable actions or key-disable mutation.

## Required independent GitHub reviewer

Use one GitHub account whose numeric user ID differs from actor/owner ID `289479481`. The person must:

1. accept write access to `trustphoneapp/keyless-cutover` so GitHub counts the review;
2. review from their own account, not a shared session;
3. be the required reviewer for the `production` environment with prevent-self-review enabled;
4. own the separate H1 repository, so its numeric owner ID is genuinely different.

Grant only the permissions required for those GitHub duties. Do not grant the GitHub reviewer project Owner, IAM Admin, service-account Token Creator, repository secrets access, or runtime-agent mutation authority.

## Separate human GCP key operator

The key operator is a separately authenticated human boundary from the Keyless runtime and may be distinct from the independent GitHub reviewer. The operator receives a fresh exact-key approval only after the reviewed merge and pre-disable evidence pass, disables—not deletes—the exact key, and appears as the human principal in Admin Activity. The Keyless runtime cannot hold or use this identity. If delegated, scope `roles/iam.serviceAccountKeyAdmin` to the exact disposable deployment service account only; the K0 owner account used for this transaction was `yashwanth.surabhi@gmail.com`.

## Authority setup

The project owner records the reviewer's GitHub login and numeric GitHub user ID, plus the separate key operator's GCP principal. Before continuing, independently read back:

- repository collaborator permission is `write`;
- `main` still requires CI, one approval, last-pusher approval, stale-review dismissal, and linear history;
- `production` requires the independent reviewer, prevents self-review, and allows protected branches only; and
- the GCP key operator is an explicit human identity outside the Keyless runtime and has disable plus rollback authority for the exact deployment key.

If any read-back is ambiguous, stop. Never work around a missing reviewer by weakening branch or environment protection.

## Reviewed ProofV2 operator transaction

The operator uses two separate commands so issuance cannot silently dispatch a workflow and verification cannot silently create a challenge. `issue` performs exactly one Firestore document creation and prints only the five bounded workflow inputs. `verify` is read-only in GitHub and Google IAM until the signed proof, exact completed run, workflow blob, and independent environment approval all agree; only then does it atomically transition the same challenge from `ISSUED` to `CONSUMED` and prove a second consume is rejected.

1. Reconfirm `main`, CI, the production reviewer, exact active user-managed key, repository/owner IDs, and five-minute operator scope.
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

## Merge sequence

### 1. Release candidate

The reviewer checks PR #11 against `main`, runs `npm ci --legacy-peer-deps --ignore-scripts`, `npm test`, and `npm audit --omit=dev --audit-level=high`, and verifies that no workflow, log, test fixture, or document contains credential material. They then approve PR #11. No one pushes to the branch after that approval. Merge only while the required `test` check is green.

PR #11 includes the earlier fixes from PRs #2 and #4–#10. Close those older PRs as superseded only after PR #11 is merged. PR #1 is obsolete documentation and may also be closed then.

### 2. Cutover candidate

After PR #11 reaches `main`, update draft PR #3 onto the new protected base without hand-editing the compiler-owned workflow. Re-run the compiler, actionlint, unit suite, dependency audit, WIF/provider read-back, impersonation-binding read-back, and downstream IAM no-widening comparison. A changed workflow byte, plan digest, provider hash, or IAM preimage requires a new review.

Mark PR #3 ready only when those checks agree. The independent person reviews and approves the exact cutover diff; a human merges it. Keyless never auto-merges.

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

1. Keep the legacy key enabled and retain the last successful `legacy-1` evidence.
2. Merge the reviewed WIF workflow and obtain a fresh `wif-1` deployment through GitHub OIDC/WIF.
3. Execute H1–H8 at their documented controls and independently verify the forbidden service is unchanged.
4. Reconstruct the pre-disable evidence ledger. Every required item must pass; one missing or unrecognized denial stops the transaction.
5. Show the independent operator the exact service account, exact key ID, evidence digest, and rollback window. The operator disables—never deletes—the exact key.
6. Read back `disabled: true` and one matching human `DisableServiceAccountKey` Admin Activity entry.
7. On a new hosted runner, execute the non-deploying legacy-auth probe. It must make a fresh Google request and receive a recognized disabled/invalid-key rejection.
8. On another new hosted runner, deploy `wif-2` through WIF and verify the allowed revision.
9. Reconstruct and credential-scan the final manifest, then sign its canonical digest with the scoped KMS key.

The immediate result may claim only: **the key is disabled, fresh key authentication is rejected, and fresh WIF authentication succeeds**. It must not claim that access tokens minted before disable were revoked.

## Rollback and kill rules

- Before key disable: revert the reviewed workflow or remove only the migration-owned WIF binding/provider after a new human review.
- After key disable: Keyless cannot re-enable the key. A human may explicitly re-enable the exact key during the short rollback window and revert the workflow.
- Never delete the key during K0.
- Stop and preserve evidence on unexpected hostile success, privilege widening, target mutation, key ambiguity, source drift, missing independent approval, secret exposure, or failed post-disable WIF deployment.
- A stopped or failed K0 remains `NO-GO`; do not repair the evidence manually or relabel it as a pass.

## Handoff data

To begin this runbook, the project owner needs only the independent person's GitHub username and the GCP identity they choose for the narrowly scoped key-operator role. Authorization codes and credentials are never handoff data.
