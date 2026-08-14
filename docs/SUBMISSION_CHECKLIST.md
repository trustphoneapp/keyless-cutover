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
- [ ] Independent K0 transaction and final receipt pass.
- [ ] Public English/subtitled video is ≤4:00 and shows backend on Google Cloud.
- [ ] Devpost form is completed and submitted before August 31, 2026 at 5:00 PM PT.

## Protected K0 release gate

- [x] Independent GitHub collaborator accepted write access.
- [x] `production` requires that reviewer and prevents self-review/bypass.
- [x] Cumulative release PR #11 has green CI and non-last-pusher approval.
- [x] PR #11 is merged; superseded stacked PRs are closed.
- [x] Cutover PR #3 is updated onto protected `main` without hand repair.
- [x] Compiler output, plan digest, provider hash, binding hash, and no-widening diff are rechecked.
- [x] Independent reviewer approves exact cutover head; human merges.
- [x] `wif-1` succeeds from the exact merged commit.
- [x] H1 uses a genuinely different numeric owner ID and reaches WIF condition denial.
- [x] H2–H7 reach their intended STS/WIF/audience controls and deny.
- [x] H8 reaches forbidden-resource Cloud Run IAM and denies.
- [x] Every hostile artifact/run/log agrees; forbidden revision is unchanged.
- [x] Pre-disable receipt reconstruction passes with no missing hostile control.
- [x] Separately authenticated human GCP operator disables—not deletes—the exact key after independent GitHub review.
- [x] Live key read-back says disabled; one exact human Admin Activity entry agrees.
- [ ] Fresh hosted legacy probe reaches Google and receives recognized key/auth denial.
- [ ] Fresh hosted WIF run creates `wif-2`.
- [ ] Credential scan is clean; `npm run verify:k0` passes from artifact bytes.
- [ ] One-byte evidence mutation fails.
- [ ] Scoped asymmetric KMS receipt signs and verifies; one-byte receipt mutation fails.

## Clean-release verification

- [ ] Clone the final public commit into an empty directory.
- [ ] Node version satisfies `>=22`.
- [ ] `npm ci --legacy-peer-deps --ignore-scripts` succeeds.
- [ ] `npm audit --omit=dev --audit-level=high` reports zero vulnerabilities.
- [ ] `npm test` passes with the published count.
- [ ] GitHub App token handling passes both classic and approximately 520-character stateless-token tests; a real app test forced with `enabled` and `disabled` succeeds before the temporary header is removed.
- [ ] `actionlint -no-color` passes.
- [ ] Console container builds for `linux/amd64` from the pinned base image.
- [ ] Agent, console, and demo `linux/amd64` images scan with zero critical/high findings.
- [ ] Private Taskmaster and public console image digests match the evidence record.
- [ ] Public console `/`, `/healthz`, and `/api/status` behave as documented; POST/mutation routes do not exist.
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
- [ ] Show `legacy-1`, ProofV2 replay rejection, `wif-1`, H1–H8, human disable, fresh legacy denial, `wif-2`, and unchanged forbidden service.
- [ ] State the token-revocation and scope limitations aloud.
- [ ] Verify KMS receipt, mutate one byte, and show verification failure.
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
