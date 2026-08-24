# Release, recording, and submission checklist

This checklist is fail-closed. An unchecked release blocker cannot be waived by better copy, screenshots, or a model-generated explanation.

## Current Stage One viability

- [x] New project built during the contest period.
- [x] Taskmaster is the single selected category.
- [x] Gemini 3.5 Flash is invoked through Vertex AI.
- [x] Google ADK is in the served path.
- [x] Google Cloud infrastructure is in the working deployment.
- [x] Public hosted evidence-console URL works without credentials.
- [x] Public repository, English documentation, license, privacy/security, and AI-assistance disclosure exist.
- [x] README contains local validation instructions.
- [x] Architecture diagram and Google-service roles are documented.
- [ ] A separately authorized fresh K0 transaction checkpoints its canonical pre-disable archive while the key remains enabled, passes disable → legacy-denial → WIF-2 ordering, authentically issues the exact pending receipt, and verifies its separately authorized scoped real KMS signature against pinned trust without changing the human release boundary. **Partially done, 2026-08-24**: archive-checkpoint-while-enabled, disable, and legacy-denial are proven on real state; WIF-2 is not achieved and is structurally blocked on this repository (see README's "The fresh transaction" section), so pending-receipt issuance and KMS signature verification were correctly not attempted.
- [ ] Public English/subtitled video is ≤4:00 and shows backend on Google Cloud.
- [ ] Devpost form is completed and submitted before August 31, 2026 at 5:00 PM PT.

## Protected K0 release gate

The prior checked transaction is historical readiness only. Its key was disabled before a canonical v3 archive checkpoint was reviewed and merged; never re-enable it or count its later missing steps toward release.

### Required fresh v3 sequence

- [x] Protected RC is independently reviewed/merged; `required_linear_history: true` and the complete branch/environment protection tuple are read back.
- [x] A separately authorized fresh disposable key transaction produces a successful baseline plus fresh ProofV2, WIF-1/parity, and H1–H8 including H2. **Done, 2026-08-24**: `legacy-3`, ProofV2 run `32761994628`, `wif-3`, all eight hostile denials.
- [ ] The exact canonical pre-disable archive checkpoint is independently reviewed, merged, and reread while the fresh key is enabled. **Review and merge done, 2026-08-24**: [PR #35](https://github.com/trustphoneapp/keyless-cutover/pull/35), check and push run both completed before disable. **Reread not done** — the reread happens inside the pending issuer (`src/k0-live-issuer.mjs`, which fetches the merged archive back and cross-checks its hash against the checkpoint record), and the pending issuer never ran.
- [x] Human operator disables—not deletes—the exact fresh key; key state and one exact Admin Activity entry agree. **Done, 2026-08-24T20:05:49Z**, principal `yashwanth.surabhi@gmail.com`, insert ID `1r9n1a8e78acr`.
- [x] Fresh hosted legacy probe reaches Google and receives a recognized denial before WIF-2 starts. **Done**: run `32771996082`.
- [ ] A later fresh hosted WIF run creates and reads back `wif-2`; WIF audit/parity and forbidden-target readback agree. **Not achieved, structurally blocked on this repository** — see README's "The fresh transaction" section for the exact audit-window and workflow-byte-pinning conflict.
- [ ] Authenticated read-only pending issuance verifies and writes the exact private output with `RECOLLECTION_REQUIRED` and `release_ready: false`. **Not attempted, correctly** — requires `post_disable` evidence that cannot exist while WIF-2 is blocked.
- [ ] A separately authorized scoped real KMS signature verifies against pinned trust; one-byte mutation fails and no release state changes. **Not attempted, correctly**, same reason.
- [ ] A separate human reviews the complete evidence and owns the release decision. Status assessed as **REVISE / NO-GO**; no release decision has been made.

### Historical readiness already observed — not v3 completion

- [x] Independent GitHub collaborator and protected `production` review existed.
- [x] Historical ProofV2, `wif-1`, H1–H8, forbidden-target readback, key disable, and Admin Activity were independently reconstructed.
- [x] Local v3 verifier, pending issuer, signature verifier, credential scan, and deterministic mutation tests pass.
- [ ] None of those historical or local facts is relabeled as a completed live v3 transaction.

## Clean-release verification

- [ ] Clone the final public commit into an empty directory.
- [ ] Node version satisfies `>=22`.
- [ ] `npm ci --legacy-peer-deps --ignore-scripts` succeeds.
- [ ] `npm audit --omit=dev --audit-level=high` reports zero vulnerabilities.
- [ ] `npm test` passes without stale count claims.
- [ ] GitHub App token handling passes both classic and approximately 520-character stateless-token tests; a real app test forced with `enabled` and `disabled` succeeds before the temporary header is removed.
- [ ] `actionlint -no-color` passes.
- [ ] Console container builds for `linux/amd64` from the pinned base image.
- [ ] Agent, console, and demo `linux/amd64` images scan with zero critical/high findings.
- [ ] Private Taskmaster and public console image digests match the evidence record.
- [ ] Public console `/`, `/_health`, and `/api/status` behave as documented; POST/mutation routes do not exist.
- [ ] Private Taskmaster rejects Cloud Run IAM alone and requires the separate application gate.
- [ ] All source/document links resolve and no private/local path appears in public copy.
- [ ] Repository and evidence artifacts pass a credential-shape scan.

## Four-minute recording

- [ ] Record at 1080p or better with readable text and English narration/subtitles.
- [ ] Start with the public console's honest state and checkpoint digest.
- [ ] Show one unedited live authorized WIF action and H4 hostile action in parallel.
- [ ] Show Cloud Run, ADK, exact Gemini model on Vertex AI, and one typed cited result.
- [ ] Show the compiler-owned PR and deterministic no-widening boundary.
- [ ] Label completed evidence `RECORDED/OBSERVED @ UTC`; label current activity `LIVE`.
- [ ] Show one fresh transaction in order: `legacy-1`, ProofV2, `wif-1`, H1–H8, merged archive checkpoint, human disable, fresh legacy denial, later `wif-2`, and unchanged forbidden service.
- [ ] State the token-revocation and scope limitations aloud.
- [ ] Verify the scoped real KMS signature on the authentically issued exact pending receipt against pinned trust, mutate one byte and show failure, and state that the signature does not authorize release.
- [ ] Show at least one GitHub run and one Google Cloud revision/audit identifier.
- [ ] Stop by 3:55; never rely on content after 4:00.
- [ ] Upload publicly to YouTube or Vimeo; verify in a signed-out browser.

## Devpost fields

- [ ] Project name and one-sentence tagline match `SUBMISSION_DRAFT.md`.
- [ ] Taskmaster category selected once.
- [ ] Hosted URL is the public Cloud Run evidence console.
- [ ] Public repository URL is correct.
- [ ] Text covers functionality, technologies, data sources, findings, and learnings.
- [ ] Architecture diagram is visible without local tooling.
- [ ] README spin-up instructions were tested from a clean clone.
- [ ] Public video URL is correct, English/subtitled, and ≤4:00.
- [ ] Final copy contains no `[PENDING]`, unsupported superlative, private identifier, credential, or stale test/evidence count.
- [ ] AI-assistance disclosure remains present.
- [ ] Submission preview works while signed out.
- [ ] Submit at least 24 hours before the deadline; save confirmation and timestamp.

## Optional bonus — only after core release

- [ ] Publish one accurate technical article/video that states it was created for this hackathon; add the link. Do not expose sensitive evidence.
- [ ] Publish one social post with `#AllThingsAgenticHackathon`; add the link.
- [ ] Do not add an extra Google model solely for bonus points. Integrate another model only if it materially improves the completed product and passes the same safety/evaluation bar.

Official source: [All Things Agentic Hackathon rules](https://allthingsagentichackathon.devpost.com/rules).
