# Development chunks and 48-hour test

## Immediate blockers

- Google Cloud CLI is installed, but no active account, ADC, project, or billing is configured.
- The local Git history is clean and reviewable, but the current fine-grained GitHub token cannot create the public remote.
- No independent reviewer/key operator or foreign-owner repository is established.
- Branch/environment protection and Gemini 3.5 Flash project access are unverified.

The K0 clock starts only after these prerequisites exist.

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
7. Independent human disables the exact key.
8. Re-read `disabled: true` through Google.
9. On a fresh hosted runner, force a new online Google token/API request with the legacy key and observe failure.
10. On another fresh run, deploy `wif-2` through OIDC/WIF.
11. Assemble a sanitized manifest and run credential scanning.

Acceptance command to implement:

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

Current local progress on August 13: the deterministic compiler/WIF plan portions of C4, the tool-free ADK schemas of C5, and the 36-case corpus/scorer/lockfile portions of C9 are implemented. C2 now has local Firestore, GitHub-observer, and Google-key-reader adapters with deterministic tests, but no live integration pass. No live Gemini result, Cloud Run ADK deployment, or sealed-case pass is claimed yet.

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
