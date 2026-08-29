# Development chunks and 48-hour test

## Immediate blockers

- The public repository, protected `main`, private `production` environment, billed GCP project, ADC, live WIF, Cloud Run services, Firestore, and Vertex Gemini access exist.
- Independent collaborator `cherala2002` provides protected PR and `production` review. The independently approved ProofV2 transaction passed; foreign-owner H1 and H2–H8 were reconstructed at their intended controls.
- The recorded WIF cutover, `wif-1`, H1–H8, and exact key disable plus matching Admin Activity are historical readiness evidence. Because no canonical v3 archive checkpoint was reviewed and merged before disable, that transaction is terminal and its key must never be re-enabled to resume it.
- The current published RC includes the local read-only pending issuer. A separately authorized fresh disposable key transaction remains human-gated from three unused release markers and secret confirmation through archive checkpoint, disable, legacy denial, `wif-2`, pending issuance, scoped signature verification, and separate human release.

No valid v3 K0 transaction is currently in progress. Every fresh live action stays under the independent authority and ordering below; local v3 reconstruction and historical evidence cannot substitute for it.

The exact independent-review, foreign-owner H1, archive-before-disable, verification, and rollback sequence is frozen in `docs/REVIEWER_RUNBOOK.md`, together with the release-marker, `production`-approval, and actor/reviewer constraints that make it executable. Historical PRs #11 and #3 are readiness evidence only. PRs #18 and #19 are merged and the 2026-08-15 protection tuple was read back. PR #27 restored the canonical cutover path; the compiler-owned WIF cutover is draft PR #28 and must not merge before the fresh legacy baseline exists. `KEYLESS_K0_ENABLED` is deliberately `false`. The next live change is a separately authorized fresh disposable key transaction; do not start it by changing `demo/release.txt` until three unused release markers are pinned and the operator is ready for H4 plus baseline dispatch.

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

1. Merge the protected RC, repair `required_linear_history: true`, and independently read back protection. **Done** (PRs #18/#19 and the 2026-08-15 read-back).
2. Authorize a new disposable key transaction and collect a fresh legacy baseline, ProofV2, WIF-1/provider/IAM parity, and H1–H8 including H2; verify the forbidden target remains unchanged.
3. Build the canonical pre-disable archive, independently review and merge its protected PR, and reread the exact bytes while the key is enabled.
4. Have the separately authenticated human operator disable the exact fresh key, then reread key state and matching Admin Activity.
5. Run the fresh hosted legacy probe and observe a recognized Google denial before WIF-2.
6. Deploy and read back `wif-2`, WIF audit/parity, and the unchanged forbidden revision.
7. Run authenticated pending issuance, separately authorize and verify the scoped KMS signature, then stop for the separate human release decision.

Accepted local bundle verification command:

```sh
node bin/k0-bundle.mjs verify .keyless/evidence/k0
```

This exact offline loader is not authenticated recollection and cannot issue or authorize a release receipt.

Any non-run, wrong enforcement point, mock, hand repair, leak, hostile success, forbidden mutation, fresh legacy success, or WIF failure kills Keyless.

## C4–C9

| Chunk | Files/outcome | Acceptance |
|---|---|---|
| C4 | Typed JSON schemas, policy/compiler, plan digest, exact patch and refusal tests | All unknown/unsafe inputs hold; compilation is byte-identical |
| C5 | One Cloud Run ADK Taskmaster using Vertex Gemini; evidence and recovery only | Ablation thresholds pass; model has no mutation/policy tools |
| C6 | Selected-repo GitHub App creates compiler-owned draft PR | Real PR opens; no merge or IAM authority |
| C7 | Local v3 bundle verifier, deterministic pending receipt, read-only pending issuer, inert KMS request, and pinned public verification are complete; authenticated live execution/evidence and a scoped real signature remain | Missing evidence or live provenance keeps `RECOLLECTION_REQUIRED`; 36/36 deterministic mutations fail |
| C8 | Repeat live harness and progressive evidence-derived console; local private-snapshot/FIFO controls are complete, hosted update remains | UI cannot synthesize `PASS` or release readiness; external state is re-read |
| C9 | 36-bundle eval, CI, lockfile, quickstart, architecture, claim audit, rehearsals, video | One release command passes from a clean clone |

Current progress through August 29: two independent live transactions each completed a fresh legacy baseline, ProofV2, the WIF cutover, `wif-1`, all eight hostile denials with the forbidden target unchanged, an archive checkpoint reviewed and merged while the key was still live, a human key disable with its matching Admin Activity entry, and a fresh online attempt with the disabled key that Google refused. The second transaction's post-disable push then deployed through WIF with no key involved. The private ADK service, Vertex call, console, sealed evaluation, v3 assembly, pending issuer, public signature verifier, and tamper tests are all implemented and tested.

The audit checks were originally pinned to Google's published example log shapes; recording the project's own live exchanges showed the real shapes differ, and the checks are now pinned to observed reality with stronger value bindings, covered by tests driven from the recorded bytes in `docs/evidence/forensics/`. The deploy step now performs a single token exchange. C3 completes with one more fresh disposable transaction on those corrected checks.

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
