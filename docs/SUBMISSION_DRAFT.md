# Devpost submission draft

> **Release status:** draft only. Do not submit or copy the target-release claims until the independent K0 cutover, authenticated pending-receipt issuance, scoped real KMS signature, and video gates pass. Replace every `[PENDING]` field with an evidence-backed value or remove the claim.

## Project identity

**Name:** Keyless Cutover

**Track:** The Taskmaster — Build a Complete Workflow, Not Just a Chatbot

**Tagline:** Migrate one GitHub Actions deployment off a permanent Google Cloud key—then prove the intended workflow still works and eight hostile identities do not.

**Hosted project:** https://keyless-evidence-208865688014.us-central1.run.app

**Source:** https://github.com/trustphoneapp/keyless-cutover

**Video:** `[PENDING — public YouTube or Vimeo URL, English, ≤4:00]`

## Short description

Long-lived Google service-account keys still end up in GitHub Actions secrets. Finding one is easy; replacing it safely is not. A rushed migration can break production deployment or trust the wrong repository, branch, workflow, event, environment, audience, or resource.

Keyless Cutover closes one bounded key-retirement transaction. It proves the exact legacy key without retrieving its private value, interprets the existing deployment path with a tool-free ADK/Gemini agent, compiles a narrowly bound Google Workload Identity Federation change, opens a human-reviewed workflow PR, runs an authorized canary plus eight hostile identity/resource tests, and only then asks a human to disable the exact key. A reconstructable receipt links the GitHub and Google Cloud evidence.

Gemini interprets variable repository and failure evidence. Deterministic code owns identity, CEL, IAM scope, workflow bytes, hostile-test verdicts, and receipt completeness. Humans own IAM application, merge, and key disable.

## The problem

Official GitHub and Google documentation explains OIDC/WIF, and security products can identify secrets that might be replaceable. The operational gap is the dangerous middle: correlate an opaque GitHub secret to the exact Google key, preserve the working deployment, constrain trust to the intended immutable identity and workflow context, prove negative identities fail at the intended controls, retire the key without losing continuity, and leave evidence another engineer can reconstruct.

This is not emergency incident response and not a generic IAM agent. V1 supports one documented workflow family, one repository, one project, one deployment service account, and one Cloud Run target. Ambiguity produces `HOLD`, never an invented migration.

## What Keyless does

1. **Observe:** parse bounded, redacted workflow evidence and authoritative GitHub/GCP metadata.
2. **Prove the key:** issue a five-minute Firestore challenge; the protected runner signs a domain-separated payload in memory; Google key metadata/certificate verification and a single transactional consume bind the exact key without exporting it.
3. **Interpret safely:** ADK with Gemini 3.5 Flash identifies the supported deployment path or a bounded recovery diagnosis, citing only supplied evidence IDs.
4. **Compile:** deterministic code produces exact WIF mappings, immutable numeric owner/repository conditions, audience, branch, workflow, event, environment, impersonation binding, and same-path workflow bytes.
5. **Review:** a selected-repository adapter opens a draft PR; humans apply IAM and approve/merge the protected workflow.
6. **Attack the replacement:** run H1–H8 across wrong owner, repository, ref, workflow, event, environment, audience, and forbidden resource. A failure before the intended control is `NOT RUN`, not success.
7. **Checkpoint before disable:** independently review, merge, and reread the canonical pre-disable archive while the fresh transaction's key remains enabled.
8. **Retire and re-prove:** only after that checkpoint, a human disables—not deletes—the exact key; a fresh legacy request must fail before a later fresh WIF deployment creates `wif-2`.
9. **Pending receipt and release boundary:** authentically recollect the exact live sources and issue the byte-exact canonical pending output with `RECOLLECTION_REQUIRED`; separately authorize and verify the scoped Cloud KMS signature, then leave release to a separate human decision. `[PENDING UNTIL K0]`

## Current working evidence

These facts describe the historical August transaction specifically, not the fresh one below. They are historical readiness evidence, not a completed-cutover claim: that key was disabled before a canonical v3 archive checkpoint was reviewed and merged, so it cannot satisfy v3 and must never be resumed by re-enabling the key. A separate, fresh disposable transaction has since run — see "Target release evidence" below for what it completed and where it stopped.

- Private Cloud Run Taskmaster using Google ADK and `gemini-3.5-flash` through Vertex AI. Cloud Run IAM plus a separate application header protect the model routes.
- Two strict, tool-free model stages: evidence classification and bounded recovery diagnosis. The model has no IAM, deployment, merge, key, shell, policy, or receipt authority.
- Second full sealed Vertex evaluation: 12/12 supported, 11 paired wins over the frozen rules baseline, 4/4 safe refusals, 8/8 recoveries, 0 forbidden outputs, and 72/72 schema-valid calls.
- Live legacy Cloud Run deployment, exact WIF provider/binding read-back, and unchanged downstream service-account permission footprint.
- Live ProofV2 run `31758449936` was independently approved by `cherala2002`, matched the exact active key and merged workflow, consumed its five-minute Firestore challenge once before expiry, rejected replay, and produced a credential-free hash-bound receipt.
- Live `wif-1` deployed through GitHub OIDC, Google STS/WIF, service-account impersonation, and Cloud Run.
- H1–H8 were reconstructed from exact runs, artifacts, and logs; each reached and denied at its named control and left the forbidden Cloud Run revision unchanged.
- Public read-only Cloud Run evidence console from an immutable image. Its runtime service account has no project roles and the served state is honestly `NO_GO_INCOMPLETE`.
- A passing deterministic local suite without a brittle published count, immutable action pins, passing Actions CI, and zero known production dependency vulnerabilities at the release audit threshold.

## Target release evidence — two independent fresh transactions, 2026-08-24 and 2026-08-25

The final description may add each statement only once its exact evidence exists. Three now do, confirmed twice independently; the fourth does not, for a structural reason found live rather than a remaining task:

- `[HISTORICAL ONLY]` The prior human key disable and Admin Activity agree, but no canonical archive checkpoint preceded them.
- **Done twice.** 2026-08-24: a fresh disposable key (`1f0137c5…`) completed baseline (`legacy-3`), ProofV2 (run 32761994628), the WIF cutover, `wif-1` (`wif-3`), and all eight hostile denials; the protected archive checkpoint (PR #35) merged, with its required check and push run both completing before the key was disabled. 2026-08-25: a second, independent fresh key (`851d4503…`) repeated the same sequence (`legacy-4`, ProofV2 run 32888780262, `wif-5`, all eight hostile denials, archive checkpoint PR #46), deliberately testing the fix for the first transaction's finding.
- **Done twice.** Fresh hosted legacy authentication was rejected after disable on a new hosted runner, reaching Google: run 32771996082 (2026-08-24) and run 32892290171 (2026-08-25).
- **Not achieved in either, for two different reasons.** 2026-08-24: a live audit-window collision (H6/H8 always added extra entries to any post-disable push). 2026-08-25: that exact fix was confirmed working live — the hostile jobs correctly skipped on the post-disable push, and `wif-6` deployed through WIF with no key involved — but the audit window still held three entries, not two, because the authentication action and `gcloud` each perform their own independent token exchange on any deploy. This is a property of the current authentication mechanism, not of hostile interference. See `README.md`'s "The second transaction" section.
- **Not attempted, correctly, in either.** Authenticated pending issuance and the scoped KMS signature both require `post_disable` evidence, which cannot exist without a certified `wif-2`. `authorization` remains `RECOLLECTION_REQUIRED`, `release_ready` remains `false`. A Cloud KMS keyring, signing key, and scoped signer service account were provisioned on 2026-08-25 and remain available.

## Google technology

| Technology | Necessary role | Judge-visible evidence |
|---|---|---|
| Gemini 3.5 Flash on Vertex AI | Variable workflow interpretation and cross-system failure diagnosis | Typed citations, sealed ablation, Vertex/Cloud Run execution |
| Google ADK | Defines and serves the bounded Evidence and Recovery agent stages | Tool-free agent definitions and served request |
| Cloud Run | Hosts the private Taskmaster, public console, allowed canary, and forbidden canary | Public URL, private-service IAM, immutable images, revision IDs |
| IAM, STS, and Workload Identity Federation | Replaces the permanent key with short-lived GitHub OIDC federation | Provider/binding hashes, real token exchange, denial matrix |
| Firestore | Issues and atomically consumes ProofV2 challenges | First consume succeeds; replay loses |
| Cloud Audit Logs | Corroborates WIF/delegation and exact human key disable | Scoped method, resource, actor, timestamp, insert ID |
| Secret Manager | Stores only the private agent's application gate | Exact accessor policy; value never enters evidence/model |
| Cloud KMS | Signs the exact canonical pending-receipt digest only after authenticated live recollection/issuance | `[PENDING]` pinned out-of-band verification and tamper failure; signature alone does not authorize release |

## Architecture and security

The [architecture](ARCHITECTURE.md) separates four authority planes:

- **Model plane:** redacted evidence in; cited interpretation/diagnosis out; no tools.
- **Deterministic plane:** identity, policy, compiler, permission diff, test oracles, and receipt verifier.
- **Human plane:** IAM application, protected review/merge, key disable, and rollback.
- **Public evidence plane:** no-role, read-only console; no secret, mutation route, Firestore, Vertex, key, or KMS access.

Repository text, workflow comments, logs, and model output are untrusted. Tokens/private keys stay in their authorized runner/tool boundary. Missing logs are not denial proof. Disabling the key does not revoke access tokens minted earlier, so the scoped result is “fresh old-key authentication failed and fresh WIF authentication succeeded,” not “all old access was revoked.”

## Data sources

- Selected GitHub workflow and at most one directly referenced local script after redaction.
- GitHub repository/run/job/workflow/environment metadata and bounded sanitized logs.
- Google service-account key metadata/certificate, WIF provider, IAM policies, Cloud Run revisions/IAM, and scoped audit entries.
- Credential-free evidence artifacts and hashes.

Keyless does not retrieve GitHub secret values, store the service-account private key, or send OIDC/access tokens, authorization headers, raw environment dumps, or unbounded repository/audit data to Gemini.

## Findings and learnings

- The hard part is not generating WIF YAML; it is proving the full transaction across two control planes without silently widening trust.
- A GitHub App cannot read an Actions secret value. Exact key correlation therefore needs a reviewed in-run proof plus Google key metadata, or an explicit human selection that stops on ambiguity.
- GitHub/GCP propagation and audit arrival are asynchronous. The four-minute demo must distinguish timestamped completed evidence from a genuinely live action.
- STS client failures may not appear in Google audit logs. A denial requires a bounded client result, immutable GitHub run identity, and independently unchanged target—not absence of a log.
- Gemini added measurable value on variable semantic and recovery cases, but it was unsafe as an authorization oracle. Deterministic security oracles remain mandatory.
- A first full model evaluation failed. The retained negative result exposed taxonomy confusion and forbidden-output repetition; only after correcting the bounded semantic contract did the second full run pass.

## Testing instructions

1. Open the [hosted evidence console](https://keyless-evidence-208865688014.us-central1.run.app). It should show `NO-GO · evidence incomplete`, a checkpoint SHA-256 digest, gates, and external evidence links. No login is required. The checkpoint path in `console/status.mjs` currently emits ten gates and three blockers; the hosted revision was built on 2026-08-13 and still serves the earlier eight-blocker rendering, so expect a mismatch until the `[PENDING]` console redeploy happens.
2. Inspect `/api/status`; `release_ready` and `cutover_verified` must currently be `false`.
3. Clone the public repository with Node.js 22+ and follow the README quickstart: install, run all tests, and run the production dependency audit.
4. Inspect `docs/evidence/CONSOLE_DEPLOYMENT_2026-08-13.json` and reconstruct its Cloud Run revision/image/IAM claims from Google Cloud evidence shown in the video.
5. Use the public video for the private Taskmaster invocation and final completed K0 transaction. Do not request or share credentials to access the private model routes.

## Limitations

- Exact v1 workflow family only; no reusable/composite auth, dynamic target, multiple plausible identities, self-hosted runner, or shared/broad service account.
- No autonomous IAM, merge, key disable, key deletion, or rollback.
- No claim of universal least privilege, absence of external key copies, zero downtime, compliance certification, or enterprise multi-tenancy.
- The receipt is scoped to the named workflow, identities, service account, resource, and evidence time.

## AI assistance disclosure

The project was built with AI-assisted research, adversarial analysis, implementation, and documentation. All security verdicts, workflow/IAM artifacts, evidence checks, test results, and release claims are controlled by deterministic code or named human gates. See [AI_ASSISTANCE.md](../AI_ASSISTANCE.md).

## Official requirements snapshot

- Deadline: August 31, 2026 at 5:00 PM PT.
- One category: Taskmaster.
- Mandatory stack: Gemini 3.5+ via Gemini API/Vertex AI, a listed Google agent framework, and Google Cloud infrastructure.
- Submission: hosted URL if available, English description, repository, README spin-up instructions, architecture diagram, and public English/subtitled YouTube or Vimeo demo ≤4 minutes.
- Judging: Innovation & Operational Utility 40%; Architectural Discipline & Tech Stack 30%; Demo & Production Readiness 30%.

Official source: [event rules](https://allthingsagentichackathon.devpost.com/rules).
