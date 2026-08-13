# Permissions and trust boundaries

> ADR 0002 removes runtime IAM mutation. Taskmaster may read evidence and open compiler-owned draft PRs; humans apply IAM and disable keys.

## Rule

Every identity gets only the permissions needed for one phase. No runtime identity can both propose and approve a high-risk change.

## GitHub App

Install only on the selected demo repository.

| Permission | Access | Purpose |
|---|---:|---|
| Metadata | read | Resolve immutable repository and owner IDs. |
| Contents | read/write | Read the supported workflow and create the Keyless branch. |
| Workflows | write | Modify `.github/workflows/*.yml`. |
| Pull requests | write | Open and update the draft migration PR. |
| Actions | read | Observe runs, jobs, conclusions, and sanitized logs. |
| Checks | write | Publish evidence status and the final receipt digest. |

The App receives no Actions-secret permission, administration permission, merge bypass, environment bypass, or organization-wide installation.

## GCP identities

### `keyless-web-sa`

- Enqueue tasks on the Keyless queue.
- Read and write public-safe migration state in Firestore.
- Access only the webhook secret required by the public service.
- Cannot invoke Google IAM, service-account-key, Cloud Run mutation, or KMS-sign APIs.

### `keyless-worker-sa`

- Invoked only by the Cloud Tasks service identity.
- Reads the selected project, service account, user-managed key metadata, IAM policy, Cloud Run service/revisions, and required audit logs.
- Creates one Keyless-owned WIF provider with a deterministic ID in the selected pool.
- Adds one exact `roles/iam.workloadIdentityUser` binding on the selected deploy service account.
- Reads/writes Firestore evidence and signs canonical receipt digests using one KMS key.
- Reads the GitHub App private key from Secret Manager and creates a short-lived installation token.

It cannot:

- disable, enable, delete, or create service-account keys;
- grant Owner, Editor, Token Creator, or project-wide IAM roles;
- merge a PR or bypass branch/environment protection;
- deploy to Cloud Run;
- retrieve a GitHub Actions secret value;
- mutate pre-existing WIF providers;
- execute arbitrary repository shell commands.

### Existing deploy service account

The cutover preserves the existing narrowly scoped deploy service account. The GitHub federated principal receives only `roles/iam.workloadIdentityUser` on that service account. Existing target-resource roles are unchanged.

If the service account is overprivileged, shared, or used by another workflow, Keyless enters `HOLD` and does not turn IAM cleanup into an implicit side project.

### Human key operator

A separate human identity owns the key-disable action. The Keyless worker can prepare the exact resource name and verification evidence but cannot call `DisableServiceAccountKey`.

## WIF condition

The deterministic compiler binds:

- immutable `repository_owner_id`;
- immutable `repository_id`;
- exact `refs/heads/main` ref;
- exact workflow path and ref;
- `push` event;
- protected production GitHub Environment;
- GitHub-hosted runner evidence where available;
- the provider's canonical default audience.

The IAM member is the exact repository-ID principal set, not the whole pool. The provider condition supplies the remaining conjunction.

## IAM write protocol

1. Read policy version 3 and its `etag`.
2. Normalize and hash the approved preimage.
3. Add only the exact approved binding.
4. Submit with the captured `etag`.
5. Read back the policy and compare semantic output.
6. Any unrelated drift invalidates approval. Do not silently rebase.

## Permission invariants

- No wildcard resources or broad pool principals.
- No privilege widening from the old deploy service account.
- No mutation without a current digest-bound approval.
- No key disable until the exact merged commit passes WIF and all eight denials pass.
- No approval is reusable across a changed SHA, provider config, IAM policy, or key state.
