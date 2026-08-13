# Developer quickstart

> This remains a planning checklist until K0 passes. Do not interpret it as reproducible live setup or proof of deployed resources.

The repository currently contains the frozen design package. Implementation begins with K0; do not scaffold the full application before the real integration transaction passes.

## Prerequisites

- A disposable `github.com` repository under your control.
- A disposable GCP project with billing and Cloud Run enabled.
- `gh`, `gcloud`, Git, Node.js, and a GitHub-hosted Ubuntu runner.
- Two humans/sessions for separation of duties: builder and independent environment/key approver.

## K0 setup checklist

1. Create dedicated `keyless-deploy@PROJECT_ID.iam.gserviceaccount.com` with only the Cloud Run permissions needed for the demo service.
2. Create one user-managed key and store it as the repository-scoped `GCP_SERVICE_ACCOUNT_KEY` Actions secret.
3. Create `keyless-demo` and `keyless-forbidden` in `us-central1`.
4. Protect `main` and create a protected `production` GitHub Environment with required review and self-review disabled.
5. Add the supported baseline workflow and deploy `legacy-1`.
6. Enable IAM, STS, Service Account Credentials, Cloud Run, Logging, and required Data Access logging for the disposable project.
7. Follow K0 in [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) and record exact identifiers in a local evidence worksheet.

## Stop conditions

Do not proceed to app scaffolding if:

- the selected service account/key cannot be proved exactly;
- the deploy service account is shared or overprivileged;
- a hostile case can obtain or use authority;
- the forbidden Cloud Run target changes;
- logs/artifacts reveal secret material;
- post-disable WIF continuity fails.

## After K0 passes

Implement in this order:

1. K1 typed schemas and deterministic state tests.
2. K2 minimal web/worker services and persistence.
3. K3 preserving observer/compiler.
4. K4 runner proof.

Use the issue template in [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md). No feature enters the build without a stated invariant, evidence output, failure behavior, and refusal behavior.
