# Changelog

## 0.2.0-k0-fixtures — 2026-08-13

- Added a digest-pinned, dependency-free Cloud Run canary and exercised it locally in Docker.
- Added one canonical static-key deployment workflow, a non-running same-path WIF template, and the H4 wrong-workflow probe.
- Pinned every GitHub Action to a full commit SHA and validated workflow syntax with `actionlint`/ShellCheck.
- Corrected ProofV2 triggering-actor binding to match GitHub's documented variables.
- Added a hash-bound plan/apply compiler that preserves the canonical workflow path and refuses drift, unpinned actions, or legacy credential retention.
- Added a deterministic WIF plan/compiler with provider-URL audience, immutable GitHub IDs, exact workflow/event/environment/runner conditions, and one narrowly scoped impersonation binding.
- Live GitHub and Google Cloud execution remains pending user-controlled authentication.

## 0.1.0-local-protocol — 2026-08-12

- Replaced the self-consistent ProofV1 shape with ProofV2 protocol primitives.
- Added random challenge issuance, authoritative expected-context construction, bounded lifetime, actor/run/workflow binding, exact active user-managed Google-key checks, and an atomic-consumer replay contract.
- Added a deterministic K0 manifest verifier that requires all eight hostile controls, immutable forbidden target, human disable, fresh legacy denial, fresh post-disable WIF success, source identifiers, and a clean leak scan.
- Added six passing local tests, including simultaneous replay rejection.
- Live GitHub/GCP evidence and Firestore-backed consumption remain unproven.

## 0.0.0-design — 2026-08-12

- Completed ten-agent architecture, security, workflow, state, development, evaluation, market, operations, UX, and final-chair research debate.
- Froze the single-repository/single-workflow/single-service v1 contract.
- Added the full design, risk, evaluation, operations, demo, and development documentation package.
- No implementation or production-readiness claim is made.
