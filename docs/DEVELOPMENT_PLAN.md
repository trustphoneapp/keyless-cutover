# Development chunks and 48-hour test

## Immediate blockers

- The public repository, protected `main`, private `production` environment, billed GCP project, ADC, live WIF, Cloud Run services, Firestore, and Vertex Gemini access exist.
- Independent collaborator `cherala2002` provides protected PR and `production` review. The independently approved ProofV2 transaction passed; foreign-owner H1 and H2–H8 were reconstructed at their intended controls.
- The exact WIF cutover and `wif-1` are live. Key disable, fresh legacy rejection, post-disable continuity, and final KMS signing remain separately human-gated.

The technical K0 substrate is running. The human-gated K0 transaction starts only when independent authority exists.

The exact independent-review, foreign-owner H1, merge, disable, verification, and rollback sequence is frozen in `docs/REVIEWER_RUNBOOK.md`. The cumulative non-cutover release is PR #11; after it merges, only the separately reviewed compiler-produced cutover PR #3 should alter the canonical deployment workflow.

## C0 — repository and authority baseline, 2h

Deliver first clean commit, public remote, license, AI-assistance disclosure, rules snapshot, Taskmaster ADR, and environment manifest.

Acceptance:

```sh
npm test
git status --short
git remote -v
gcloud auth list --filter=status:ACTIVE
gcloud config get-value project
```

Stop if project provenance or rule eligibility cannot be established.

## C1 — disposable substrate, 4h

Create a public protected repository, `production` environment with prevent-self-review, second-owner hostile fixture, disposable billed GCP project, narrow deploy/runtime service accounts, `keyless-demo`, `keyless-forbidden`, and one repository secret. Deploy and read back `legacy-1` from a new hosted runner.

Stop for shared/broad accounts, unavailable review controls, or credential exposure.

## C2 — complete ProofV2, 4h

Add:

- Firestore server challenge with 256-bit nonce and five-minute expiry.
- Atomic `ISSUED → CONSUMED` transaction.
- GitHub API refetch of the exact run, attempt, workflow path/ref/blob and commit.
- Actor ID, triggering-actor login, runner environment, event, ref, and environment binding.
- Authenticated Google `serviceAccounts.keys.get` verification of exact user-managed enabled key.
- Live Google certificate integration test.
- Replay/race, wrong expected context, expiry, malformed metadata, and leak tests.

The reviewed proof step runs inside the selected protected deployment workflow before the final WIF patch.

Stop if the exact key remains ambiguous, any replay wins twice, or private material leaves the hosted runner.

## C3 — authoritative K0, 12h within 48 wall-clock hours

1. Human reviews and applies the exact WIF provider and service-account impersonation binding.
2. Read back the provider, audience, mappings, condition, IAM policy version/etag, and normalized permission footprint.
3. Wait with bounded polling; IAM changes may take minutes and can exceed seven minutes.
4. Merge the static-key → WIF patch and deploy `wif-1`.
5. Execute H1–H8 at their intended controls.
6. Verify `keyless-forbidden` is unchanged.
7. Separately authenticated human GCP operator disables the exact key after independent GitHub review.
8. Re-read `disabled: true` through Google.
9. Dispatch the separate protected `k0-legacy-auth-check.yml` workflow on a fresh hosted runner, force a new online Google token/API request with the legacy key, and observe a Google key-related denial. The canonical deploy workflow has already been replaced and cannot provide this probe.
10. On another fresh run, deploy `wif-2` through OIDC/WIF.
11. Assemble a sanitized manifest and run credential scanning.

Implemented acceptance command:

```sh
npm run verify:k0 -- .keyless/evidence/k0/manifest.json
```

Any non-run, wrong enforcement point, mock, hand repair, leak, hostile success, forbidden mutation, fresh legacy success, or WIF failure kills Keyless.

## C4–C9

| Chunk | Files/outcome | Acceptance |
|---|---|---|
| C4 | Typed JSON schemas, policy/compiler, plan digest, exact patch and refusal tests | All unknown/unsafe inputs hold; compilation is byte-identical |
| C5 | One Cloud Run ADK Taskmaster using Vertex Gemini; evidence and recovery only | Ablation thresholds pass; model has no mutation/policy tools |
| C6 | Selected-repo GitHub App creates compiler-owned draft PR | Real PR opens; no merge or IAM authority |
| C7 | Firestore evidence view, canonical receipt, asymmetric KMS sign/verify | Missing evidence blocks final; one-byte mutations fail |
| C8 | Repeat live harness and minimal evidence-derived console | UI cannot synthesize `PASS`; external state is re-read |
| C9 | 36-bundle eval, CI, lockfile, quickstart, architecture, claim audit, rehearsals, video | One release command passes from a clean clone |

Current live progress through August 14: C0–C2 and the human-disable portion of C3 are complete. Independently approved ProofV2 passed, the exact WIF workflow is merged, `wif-1` is live, deterministic collectors prove H1–H8 at their intended controls with the forbidden revision unchanged, and the exact legacy key is disabled with matching human Admin Activity. A private Cloud Run ADK service, a real dual-auth Vertex call, the public fail-closed console, and the passing 72-call sealed evaluation also exist. C3 remains incomplete because fresh legacy rejection and post-disable `wif-2` are still missing.

## Calendar

- August 12–13: C0 and prerequisites.
- August 13–15: C1–C3 and unconditional K0 decision.
- August 16–20: C4–C7.
- August 21–24: C8 and integration buffer.
- August 25–27: C9, security and documentation freeze.
- August 28: record demo.
- August 29: independent judge/red-team review.
- August 30: evidence-backed corrections only.
- August 31: final verification and early submission.

No new feature enters after August 24.
