# Keyless Cutover

Keyless Cutover is a Taskmaster-track hackathon project for one risky security transaction: replace one long-lived Google service-account key used by one GitHub Actions deployment with narrowly bound Workload Identity Federation (WIF), prove both deployment continuity and hostile-identity denial, require humans at the IAM, merge, and key-disable boundaries, and produce a reconstructable receipt.

## The problem

Security teams know permanent cloud keys should be retired, but a bad migration can break deployments or trust the wrong repository. Existing scanners find replaceable secrets and official guides explain WIF; neither completes and proves the full cutover.

The target user is a platform-security or cloud-IAM engineer at a GCP-heavy software company. The job is:

> Close one key-retirement ticket with evidence that the intended deployment still works, trust did not widen, tested hostile identities failed, and the exact legacy key was disabled by a human.

Keyless is for proactive credential retirement, not emergency incident response.

## Exact v1 scope

- One public `github.com` repository, protected `main`, protected `production` environment, and canonical deployment workflow.
- One repository-scoped JSON secret containing one disposable user-managed GCP key.
- One narrowly scoped deployment service account.
- One allowed and one forbidden Cloud Run service.
- One ADK Taskmaster using `gemini-3.5-flash` through Vertex AI for sourced evidence interpretation and bounded failure diagnosis.
- Deterministic code owns CEL, IAM/resource identifiers, workflow patch bytes, policy decisions, hostile-test verdicts, and receipt completeness.
- Humans apply the reviewed WIF/IAM bundle, merge the PR, and disable the exact key.

## Before and after

```text
Before: GitHub secret → long-lived private key → deploy service account → Cloud Run
After:  GitHub OIDC → Google STS/WIF → same deploy service account → Cloud Run
```

Preserving the service account avoids changing downstream resource roles during the authentication cutover. It does not prove that the existing service account was already least-privileged.

## Minimal Google-native architecture

```mermaid
flowchart LR
    O["Operator"] --> A["Taskmaster on Cloud Run"]
    A --> V["ADK + Gemini 3.5 Flash on Vertex AI"]
    A --> F["Firestore challenge and operation state"]
    A --> G["GitHub draft PR"]
    H["Human IAM and merge gates"] --> G
    G --> OIDC["GitHub OIDC"]
    OIDC --> W["Google STS / WIF"]
    W --> SA["Existing deploy service account"]
    SA --> CR["Allowed Cloud Run service"]
    SA -. denied .-> X["Forbidden Cloud Run service"]
    A --> K["Cloud KMS receipt signature"]
    C["Public read-only evidence console"] --> E["Credential-free checkpoint or verified K0 bundle"]
```

Firestore exists for one-time ProofV2 challenge consumption and evidence-derived operation state. KMS is added only after the real 48-hour transaction passes. Cloud Tasks, Pub/Sub, Agent Engine, Registry, Memory Bank, autonomous IAM mutation, and a multi-agent fleet are intentionally outside the hackathon build.

## Safety contract

- Keyless never receives the private-key value and never persists or sends GitHub OIDC tokens, Google access tokens, or HTTP authorization headers to Gemini. The private Cloud Run service uses Google IAM for caller identity plus a separate `X-Keyless-API-Token` application gate; neither credential is logged or model-bound.
- Gemini never chooses authoritative repository, project, service account, key, provider, role, or target identifiers.
- A model output can never produce `PASS`, authorize IAM, merge a PR, disable a key, or complete a receipt.
- A human applies IAM, another protected review gates the workflow, and a human disables the key.
- A failed, missing, timed-out, or unexecuted hostile test is not a denial.
- KMS proves receipt origin and tamper resistance, not that external events happened.
- Disabling a key blocks fresh authentication but does not revoke access tokens minted earlier.

## Current status — August 14, 2026

Implemented locally:

- Git repository initialized.
- Node ProofV2 protocol primitives for random challenge issuance without a preselected key ID, separately expected authoritative context, a five-minute maximum window, active user-managed Google-key validation, bounded certificate lookup, and atomic-consumer replay rejection.
- Deterministic K0 v2 evidence-manifest verifier with fixed H1–H8 controls, typed/hashed GitHub and GCP evidence, unchanged-target requirements, cross-reference integrity, and false-safe rejection.
- Sixty-one passing local tests, including a simultaneous replay race, the Cloud Run canary and evidence-console contracts, documentation-link integrity, exact cutover compilation, immutable WIF trust/readback planning, strict ADK invocation/output/citation contracts, three-repeat deterministic evaluation thresholds, Firestore transitions, GitHub observation, canonical numeric-service-account audit lookup, authenticated Google key readback, hostile and fresh-legacy denial collection, crash-window-aware draft PR creation, the reviewed ProofV2 operator transaction, pre-disable and disable receipt reconstruction, and offline evidence reconstruction.
- A locally built and exercised digest-pinned canary container.
- One canonical legacy deployment workflow, a non-running WIF cutover template preserving the same workflow path, and the H4 wrong-workflow probe; all actions are SHA-pinned and `actionlint` passes.
- The WIF template now executes H3 (fixed hostile branch), H5 (manual event), H6 (staging environment), H7 (wrong audience), and H8 (valid identity mutating the forbidden service) as explicit expected-denial jobs. A frozen external-repository template drives H1/H2; H4 remains the wrong-path workflow. Each expected denial emits a small credential-free artifact with platform run identity and actual step outcome; every workflow passes `actionlint` locally.
- A deterministic plan/apply compiler that refuses source drift, template drift, unpinned actions, credential retention, or workflow-path changes and emits byte-identical reviewed WIF workflow content.
- A deterministic WIF compiler that binds numeric owner/repository IDs, protected `main`, the canonical workflow, `push`, `production`, GitHub-hosted runners, provider URL audience, one impersonated service account, and only `roles/iam.workloadIdentityUser`.
- Two tool-free ADK `LlmAgent` stages pinned to `gemini-3.5-flash`: bounded evidence classification and allowlisted failure diagnosis. Their Zod schemas reject extra fields, and deterministic post-validation requires every cited evidence ID to exist in the supplied redacted bundle.
- A 36-case corpus (12 visible development, 12 sealed supported, 4 sealed refusal, 8 sealed recovery), a frozen rules-only baseline, and a raw-count evaluator that rejects forbidden model content.
- A sequential sealed-evaluation runner that performs exactly three isolated attempts for each of 24 sealed cases, emits only structured outputs or a fixed rejection code, and requires at least 70/72 schema-valid calls plus the documented case-majority gates.
- A Firestore challenge store with create-once issuance, transactional `ISSUED → CONSUMED` transition, expiry enforcement, and digest binding; an authoritative GitHub observer that rebuilds the proof context from a completed run, workflow blob, and independent environment review; and an ADC-backed exact Google key reader.
- A fail-closed ProofV2 operator with separate `issue` and `verify` commands. It emits only the five bounded dispatch inputs, accepts GitHub credentials only through an environment variable, refetches the exact run/workflow/artifact/reviewer, validates the active Google key and certificate, atomically consumes once, rejects replay, and reconstructs the exact receipt after a crash that occurs immediately after consumption.
- A private, bounded Node HTTP service that runs the two tool-free ADK stages, revalidates every final output, and disables OpenTelemetry export in its pinned container. Cloud Run IAM authenticates an invoke-only operator and a separate `X-Keyless-API-Token` gates the model routes. A real served Vertex Gemini 3.5 Flash request passed both gates; IAM alone reached the app and was rejected with 401.
- A dependency-free, read-only evidence console that renders only a validated credential-free checkpoint or a fully verified K0 manifest/artifact bundle. It contains no client script or mutation route, rejects self-asserted success, and keeps a verifier-passing but unsigned cutover in `K0_VERIFIED_RECEIPT_PENDING` rather than declaring release success.
- A canonical evidence-artifact format and semantic verifier: every K0 ledger digest must resolve to matching credential-free `artifacts/E###.json` bytes, and their contents must agree with the claimed key, WIF hashes, hostile identity/run/control, unchanged revision, human disable, legacy denial, and `wif-2` result.
- A selected-repository GitHub adapter that rechecks numeric owner/repository IDs, protected base SHA, live workflow bytes, and approved plan before creating compiler-owned branch bytes and a draft PR. It never merges and safely reuses only exact branch/PR residue after a retry.
- A GitHub hostile-run collector that refetches the completed run/job, downloads the bounded platform artifact and job log through trusted redirects without forwarding authorization, correlates immutable context, and recognizes only allowlisted Google STS/audience/Cloud Run denial signatures. Generic setup/network failures remain unproven.
- An ADC-backed Google evidence reader and WIF readback verifier that hashes the exact live provider configuration, permits only the approved repository impersonation binding as the service-account IAM delta, proves the allowed/forbidden Cloud Run IAM policies are semantically unchanged, and normalizes the latest ready revision.
- A protected manual legacy-auth workflow and collector that remain available after the canonical workflow becomes WIF, force a fresh Google request with the exact old key on a new hosted runner, and accept only a Google key/authentication rejection signature. The workflow cannot deploy.
- A bounded Cloud Logging query that accepts exactly one successful `DisableServiceAccountKey` Admin Activity entry for the scoped key, expected human principal, and approved 24-hour-or-shorter window; ambiguity blocks final evidence.
- Google Cloud CLI installed.

Live but incomplete:

- The public [Keyless evidence console](https://keyless-evidence-208865688014.us-central1.run.app) is deployed on Cloud Run revision `keyless-evidence-00001-82l` from an immutable amd64 image. Its dedicated runtime identity has no project role and the expected hardened response headers. The deployed image still serves the earlier eight-blocker checkpoint; the current local checkpoint now has three blockers and requires a separately authorized console rebuild/deploy.
- The billed project `keyless-k0-20260813`, private Cloud Run agent, `legacy-1` canary, forbidden canary, Firestore database, reviewed WIF provider/binding, merged compiler-produced cutover, and live `keyless-demo-wif-1` revision exist. Provider/IAM readback matches the approved hashes and adds no downstream service-account permission.
- ProofV2 run `31758449936` executed on merged commit `f48d9f1b9ac1d321c6b953217b50df82cd59ca4d` after protected `production` approval by `cherala2002`. It matched the exact active user-managed key, atomically consumed challenge `2dda9f12-07fd-4255-8bcd-61aea76dabdb` before expiry, rejected replay, survived receipt reconstruction after consumption, and passed an independent credential-shape scan. The credential-free [ProofV2 receipt](docs/evidence/PROOFV2_RECEIPT_2026-08-14.json) records the exact hashes and limitations.
- PR #14 established the hardened reviewed workflow, PR #15 added the fail-closed operator, and PR #16 recorded the verified pre-disable state. All merged with independent review and passing post-merge CI.
- H1–H8 were independently reconstructed from their exact GitHub runs, artifacts, and job logs. All eight reached and denied at the intended WIF/audience/Cloud Run control, including foreign-owner H1 from `cherala2002/keyless-h1-probe`; `keyless-forbidden-00001-rvf` remained unchanged. The credential-free [pre-disable receipt](docs/evidence/K0_PREDISABLE_RECEIPT_2026-08-14.json) records the exact run, artifact, and log hashes.
- Human operator `yashwanth.surabhi@gmail.com` disabled—not deleted—the exact key `253d40858619a76541f1b6374d157560cf8b14f6`. Live key readback reports `disabled: true`; the credential-free [disable receipt](docs/evidence/K0_DISABLE_RECEIPT_2026-08-14.json) binds the exact Admin Activity method, actor, timestamp, insert ID, numeric service-account identity, and key ID.
- The second full sealed Vertex evaluation passed 12/12 supported cases, 11 paired wins over rules-only, 4/4 refusals, 8/8 recoveries, 0 forbidden outputs, and 72/72 schema-valid calls. The first run failed and is retained locally as negative evidence.

Not yet proven:

- Fresh hosted legacy rejection, post-disable `wif-2`, KMS receipt, updated evidence-console deployment, or video.

The project remains **REVISE / NO-GO** until the 48-hour K0 test passes. No live security outcome is claimed from the local unit tests.

## 48-hour kill gate

K0 must produce real `legacy-1`, `wif-1`, and post-disable `wif-2` Cloud Run revisions; consume ProofV2 once; deny H1–H8 at their intended controls; keep the forbidden service unchanged; observe the exact key disabled by a human; reject a fresh online legacy authentication attempt; and produce a reconstructable, credential-free manifest.

Any mocked core evidence, replay acceptance, hostile success, secret leak, wrong-key ambiguity, hand-repaired generated patch, or failed post-disable WIF deployment kills or pivots the project.

## Documentation

- [Master plan](docs/MASTER_PLAN.md)
- [Development chunks](docs/DEVELOPMENT_PLAN.md)
- [Ten-agent debate](docs/RESEARCH_DEBATE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Support and hostile-test matrix](docs/SUPPORT_MATRIX.md)
- [Evaluation gates](docs/EVALUATION.md)
- [Independent reviewer and K0 operator runbook](docs/REVIEWER_RUNBOOK.md)
- [Four-minute demo](docs/DEMO_RUNBOOK.md)
- [Devpost submission draft](docs/SUBMISSION_DRAFT.md)
- [Release and submission checklist](docs/SUBMISSION_CHECKLIST.md)
- [Official source index](docs/SOURCES.md)
- [ADR 0002: Taskmaster scope](docs/adr/0002-TASKMASTER_SCOPE.md)

## Development

```sh
npm ci --legacy-peer-deps --ignore-scripts
npm test
npm audit --omit=dev --audit-level=high
npm run run:eval -- predictions.json
npm run score:eval -- predictions.json
```

Node 22 or newer is required. Live setup instructions will be added only after K0 is reproducible.

## Track and judging position

- Track: **The Taskmaster — Build a Complete Workflow, Not Just a Chatbot**.
- Current judge-style estimate: Stage One fail; counterfactual 52/100.
- Projected only after every gate: approximately 90/100 under the official 40/30/30 weighting.

These are internal estimates, not organizer scores or a guarantee of winning.
