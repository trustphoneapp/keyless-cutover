# Developer quickstart

This quickstart validates the public source without granting cloud authority or replaying the live disposable cutover. The final live-operator setup remains gated by K0 and `REVIEWER_RUNBOOK.md`.

## Requirements

- Node.js 22 or newer.
- Git.
- `gh` and `gcloud` only for authorized live operators; local tests do not need cloud credentials.

## Validate a clean checkout

```sh
npm ci --legacy-peer-deps --ignore-scripts
npm test
npm audit --omit=dev --audit-level=high
```

The current release candidate has 49 deterministic tests and zero known production dependency vulnerabilities at the configured audit threshold. The test suite also fails on unreviewed dependency-tree problems, unpinned workflow actions, an unpinned ProofV2 runtime, hidden proof-artifact paths, or package-manager tooling in final containers.

## Validate deterministic artifacts

The compilers consume explicit reviewed JSON and never discover or receive a private key value:

```sh
npm run plan:wif -- wif-input.json wif-plan.json
npm run cutover -- plan .github/workflows/k0-deploy.yml k0/templates/k0-deploy.wif.yml cutover-plan.json
npm run cutover -- apply .github/workflows/k0-deploy.yml k0/templates/k0-deploy.wif.yml cutover-plan.json k0-deploy.generated.yml
npm run verify:k0 -- evidence/k0/manifest.json
```

`verify:k0` requires the manifest and sibling `artifacts/E###.json` files. Missing, unreferenced, noncanonical, tampered, semantically inconsistent, or credential-shaped evidence fails verification.

## Evaluate agent necessity

```sh
npm run run:eval -- predictions.json
npm run score:eval -- predictions.json
```

Live evaluation requires valid Vertex AI application-default credentials and the configured Gemini model. Raw model outputs are local evidence and must not be committed. Security verdicts are always deterministic; the model does not judge authorization or receipt completeness.

## Live K0

Do not reproduce K0 by copying credentials from another project. Use a disposable project/repository, a dedicated deployment service account, protected `main`, protected `production`, a human reviewer/key operator, and the exact support matrix. Follow [Development chunks](DEVELOPMENT_PLAN.md) and the [independent reviewer/operator runbook](REVIEWER_RUNBOOK.md).

Stop on key ambiguity, shared or broad authority, source drift, missing review, hostile success, forbidden-target change, secret exposure, or failed post-disable WIF continuity.
