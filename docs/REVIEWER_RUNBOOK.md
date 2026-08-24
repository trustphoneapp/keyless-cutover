# Independent reviewer and K0 operator runbook

This runbook is the human gate for the live Keyless K0 transaction. It does not authorize anyone to share a browser authorization code, private key, GitHub secret, access token, ID token, or application token. Keyless never needs those values in chat, a pull-request comment, or an evidence artifact.

## Historical stop state before the reviewed ProofV2 milestone — superseded

- `release/live-agent-v2` was the cumulative non-cutover release candidate in PR #11.
- `keyless/k0-live` was the compiler-produced WIF cutover in draft PR #3.
- `KEYLESS_K0_ENABLED` was `false`.
- The exact legacy service-account key remained enabled.
- At that checkpoint H2 was proven while H1 and H3–H8 were incomplete.
- At that checkpoint no reviewer other than the repository owner had qualifying authority.

Those historical conditions are superseded. PR #3 is merged, `wif-1` is live, reviewed ProofV2 passed, deterministic collectors prove H1–H8 with the forbidden revision unchanged, and the exact key is now disabled with matching human Admin Activity. `KEYLESS_K0_ENABLED` is `false` again: it was deliberately set to `false` at `2026-08-21T20:53:33Z`, before PR #27 merged, and it is the kill switch that keeps every deploy and hostile job from starting. Read it back before and after each step of the live order below; an operator must set it to `true` only when the fresh transaction is actually starting, and back to `false` when it stops. That transaction is nevertheless terminal historical readiness evidence: no canonical v3 pre-disable archive checkpoint was reviewed and merged before disable. Do not continue it, do not run its missing post-disable steps, and never re-enable its key to try to make it pass. A v3 result requires the separately authorized fresh disposable transaction below.

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

## Release markers

Both deploy workflows read `demo/release.txt`, enforce `^[a-z0-9][a-z0-9-]{0,19}$` on it before authenticating, and pass it to `deploy-cloudrun` as `suffix:`. The revision is therefore named `keyless-demo-<marker>`, and `src/gcp-evidence.mjs` and `src/github-workflow-snapshot.mjs` enforce the same shape when they read a revision or a run back.

Cloud Run refuses a revision name that already exists, so a marker is single-use. These `keyless-demo` revisions already exist and their markers are burned:

| Revision | Burned marker |
|---|---|
| `keyless-demo-00001-z26` | initial service revision, not created from a marker |
| `keyless-demo-legacy-1` | `legacy-1` |
| `keyless-demo-legacy-2` | `legacy-2` |
| `keyless-demo-wif-1` | `wif-1` |
| `keyless-demo-wif-1-31909473500-wif-1` | `wif-1-31909473500-wif-1` |

`demo/release.txt` on `main` currently holds `wif-1`, which is burned. Before the fresh transaction starts, pick three unused markers that satisfy the regex and collide with no name above. A reused marker fails the deploy step, and a failed deploy is not evidence of anything.

The two hostile repositories use their own `demo/release.txt` only as a `push` path filter — they never reach `deploy-cloudrun`, so they burn no Cloud Run revision. They still need a genuinely new value each run, because writing the same bytes produces no commit and therefore no push event. `h1-fresh-1` in `cherala2002/keyless-h1-probe` and `h2-fresh-1` in `trustphoneapp/keyless-hostile` are already used.

## Live K0 order

Read this whole section before touching anything. The order below is structural: it is what the workflow triggers, the branch/environment protection, and `src/k0-evidence-semantics.mjs` allow, not a preference.

### Standing constraints

- **`trustphoneapp` merges and dispatches; `cherala2002` only reviews.** The verifier rejects any `GITHUB_PULL_REQUEST` artifact where `author_id === reviewer_id` and any `GITHUB_ENVIRONMENT_REVIEW` artifact where `actor_id === reviewer_id`. The run actor is whoever pushed or dispatched, so if `cherala2002` merges a marker PR or dispatches a workflow, their own `production` approval stops being independent and that evidence is rejected. Neither hostile repository has branch protection, so nothing in GitHub enforces the distinct-author rule on the H1 and H2 approval PRs — the operator must hold that line manually.
- **`KEYLESS_K0_ENABLED` is the kill switch.** Every deploy and hostile job is gated on `vars.KEYLESS_K0_ENABLED == 'true'`. It is currently `false`. Set it to `true` only when the transaction is actually starting, and set it back to `false` when the transaction stops for any reason. A job skipped because the switch was off is `NOT RUN`, never a denial.
- **Three separate release-marker PRs are required.** The WIF workflow's `deploy` job runs only on `github.event_name == 'push'` to `refs/heads/main`, and the workflow's `push` trigger is filtered to `paths: demo/release.txt`. `main` requires one approving review, last-push approval, stale-review dismissal, a green `test` check, and linear history, so every change to `demo/release.txt` is its own reviewed PR. The transaction needs one for the fresh legacy baseline marker, one for `wif-1`, and one for `wif-2`.
- **Each `demo/release.txt` push also starts H4.** `.github/workflows/k0-hostile-wrong-workflow.yml` shares the same `push`/`paths` trigger, so it runs on every marker merge. Do not merge a marker PR until the operator is ready to approve and collect H4 as well.
- **`production` approval is required for almost every run.** The `production` environment requires `cherala2002` with prevent-self-review and allows protected branches only. That means each of these waits on a human approval before its job starts: the legacy baseline dispatch, ProofV2, the `wif-1` and `wif-2` deploys, H3, H4, H5, H7, H8, the H1 and H2 external runs, and the post-disable legacy-auth probe. H6 targets the `staging` environment, which has no protection rules, so it is the one run that starts without an approval — that is the point of H6.
- **STS data-access audit logging must stay on.** WIF audit evidence comes from `sts.googleapis.com` data-access logs, which were enabled on project `keyless-k0-20260813` on 2026-08-24 (`DATA_READ` and `DATA_WRITE`). They were off before that and audit logs are not retroactive, so no WIF exchange recorded earlier can be re-collected. Read the audit config back before step 4; if it is off, turn it on and start the transaction after that, not before.
- **Two WIF providers exist in the `keyless-k0` pool.** `.../providers/github` is the approved one; both `GCP_WIF_PROVIDER` and `GCP_WIF_AUDIENCE` point at it and its live config hash matches the approved plan. `.../providers/github-fresh-wif1` is orphaned: it pins a workflow path that no longer exists on `main` and is waiting on a human deletion. Do not point any variable at it, and do not delete it mid-transaction.
- **The 48-hour clock opens at the first approval PR review, not at the first workflow run.** `occurrenceValues` in `src/k0-evidence-semantics.mjs` returns `[reviewed_at, merged_at]` for every `GITHUB_PULL_REQUEST` artifact, and the gate takes the earliest occurrence across all final evidence and requires `manifest.assembled_at` to be no more than 48 hours later. The manifest carries five approval-workflow PRs (`baseline`, `h1`, `h2`, `h4`, `legacy`) plus the cutover PR and the archive-checkpoint PR, so in this order the first approval PR review is what opens the window. Note the rule is the earliest authoritative *occurrence*, not specifically a review: `moments` also carries every pre-disable record's `recorded_at` and the checkpoint event times, so recording an observation before the first review would start the clock instead. Do not review the H1 or H2 approval PR days ahead of the rest; every one of them must be reviewed inside the same window as the final collection.

### Sequence

1. Merge the protected RC, repair `required_linear_history: true`, and independently read back the complete branch and environment protection tuple. **Done** at `2026-08-15T06:02:22Z`; see `docs/evidence/REPOSITORY_PROTECTION_2026-08-15.md`. Re-read it immediately before step 2; a later difference stops the transaction.
2. Under separate authorization, create the fresh disposable key, confirm the GitHub secret holds exactly that key, and pin the three unused release markers. Set `KEYLESS_K0_ENABLED` to `true` only now.
3. Open and independently review the five approval-workflow pull requests (`baseline`, `h1`, `h2`, `h4`, `legacy`) that pin the exact workflow bytes in this repository and in the two hostile repositories. The earliest of these reviews opens the 48-hour window, so review them together and immediately before the run — not days ahead.
4. Run `node bin/k0-predisable-collect.mjs observe-forbidden` to record the forbidden revision **before** the first hostile probe starts. This observation must precede H8's start time, and the collect plan cannot be written until H8 exists, so it cannot be recovered later.
5. Merge the baseline release-marker PR, then dispatch the legacy workflow, approve `production`, and collect the fresh legacy baseline revision. This is the first of the three marker PRs.
6. Run ProofV2. Issue the challenge only when the dispatcher is ready: expiry is exactly five minutes (`MAX_CHALLENGE_LIFETIME_MS` in `src/key-proof.mjs`), and an expired challenge can never be re-dispatched or reissued without a new explicit write permission. `trustphoneapp` dispatches with the five printed inputs; `cherala2002` approves `production`; then verify and consume once.
7. Review and merge the compiler-owned cutover PR (currently draft PR #28) so the canonical workflow becomes the WIF template. This must not merge before the fresh legacy baseline in step 5 exists, because the compiler's `current_sha256` is the legacy baseline content.
8. Merge the `wif-1` release-marker PR. That single push starts **five** jobs, because `deploy`, `h6-wrong-environment`, `h7-wrong-audience`, and `h8-forbidden-resource` all carry the identical `if:` condition (`push` on `refs/heads/main`) inside the WIF workflow, and `k0-hostile-wrong-workflow.yml` shares the same `paths: demo/release.txt` trigger. Expect to approve four `production` runs at once (`deploy`, H4, H7, H8); H6 targets `staging`, which has no protection rules, so it runs unattended. Read back the exact `wif-1` revision and prove provider/IAM parity with no added downstream service-account permission.
9. Run the remaining hostile probes and collect each at its intended control. Only H3 (a push to branch `keyless-h3`) and H5 (a `workflow_dispatch`) are separate runs; H4 and H6–H8 already fired on the step 8 marker push. H1 comes from the foreign-owner repository and H2 from the wrong-repository fixture, each needing its own independently reviewed approval PR. Verify the forbidden revision is unchanged against the step 4 observation.
10. Run `node bin/k0-predisable-collect.mjs collect` to assemble the bundle input, archive plan, and checkpoint receipt from the exact live sources.
11. Build the canonical pre-disable archive with `node bin/k0-predisable-archive.mjs`, commit it through a protected PR, obtain independent review of its exact head, merge it, and read back the exact archive bytes **while the fresh key is still enabled**. The verifier requires the checkpoint's `test` check and `main` push run to complete strictly before the disable audit timestamp, so a checkpoint merged after disable can never be repaired. Any missing source stops the transaction.
12. Show the human key operator the exact fresh service account, key ID, archive digest, and rollback window. The operator disables—never deletes—the exact key; independently read back `disabled: true` and one matching `DisableServiceAccountKey` Admin Activity entry.
13. On a new hosted runner, dispatch the non-deploying legacy-auth probe and approve `production`. It must make a fresh Google request and receive a recognized disabled/invalid-key rejection. Complete this denial before WIF-2.
14. Only after legacy denial, merge the `wif-2` release-marker PR — the third and last one. **Approve the `deploy` run only. Leave the H4, H7, and H8 runs from this push unapproved.** The WIF audit lookup reads the window `[deploy job started_at, wif-2 revision createTime]` and `projectWifAuditEvidence` throws unless it finds exactly two entries: the STS `ExchangeToken` and the IAM `GenerateAccessToken` from the deploy itself. A `production` job that is never approved never starts, so it authenticates nothing and writes no audit entry. H6 targets `staging`, which has no protection rules, so it runs unattended at push time — before the deploy job is approved, and therefore before the window opens. All of H3–H8 were already collected from the step 8 and step 9 runs; these repeats are not evidence and must not be approved. Then read back the exact allowed revision, WIF audit, parity, and unchanged forbidden revision.
15. Run the local authenticated read-only pending issuer against those exact sources. Verify its private canonical output; status remains `K0_VERIFIED_RECEIPT_PENDING`, authorization `RECOLLECTION_REQUIRED`, and `release_ready: false`.
16. Through separate authorization, obtain the scoped real KMS signature and verify it against pinned out-of-band public trust. The signature changes no release state.
17. Set `KEYLESS_K0_ENABLED` back to `false`. A separate human reviews the complete evidence and owns any release decision outside the local state machine.

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
