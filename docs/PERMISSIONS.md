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
| Checks | write, after K0 | Publish evidence status and the final receipt digest. |

The App receives no Actions-secret permission, administration permission, merge bypass, environment bypass, or organization-wide installation.

## GCP identities

### `keyless-agent-sa`

- Runs the single Taskmaster Cloud Run service.
- Invokes the fixed Gemini model through Vertex AI.
- Reads/writes only the Firestore challenge and evidence-state collections.
- Reads the selected service-account key metadata, WIF/provider configuration, IAM policy, Cloud Run service/revisions, and required audit entries.
- Reads only the exact Secret Manager versions for the HTTP bearer token and, after C6, the selected-repository GitHub App credential.

It cannot create/update/delete WIF providers or IAM bindings; disable, enable, delete, or create service-account keys; deploy to Cloud Run; sign a receipt; merge a PR; retrieve an Actions secret value; or execute arbitrary repository shell commands.

### `keyless-receipt-sa` — after K0 only

- Invoked only by the deterministic receipt-finalization path after the complete K0 evidence bundle verifies.
- May use one asymmetric Cloud KMS key version to sign a canonical receipt digest.
- Cannot read repository credentials, mutate GitHub/GCP infrastructure, or decide evidence completeness.

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

## Human IAM write protocol

1. Read policy version 3 and its `etag`.
2. Normalize and hash the approved preimage.
3. Present the exact reviewed provider and binding command bundle to the human IAM operator.
4. The human adds only the exact approved binding using the captured preimage/`etag` where the API supports it.
5. Read back the policy and compare semantic output.
6. Any unrelated drift invalidates approval. Do not silently rebase.

## Permission invariants

- No wildcard resources or broad pool principals.
- No privilege widening from the old deploy service account.
- No mutation without a current digest-bound approval.
- No key disable until the exact merged commit passes WIF and all eight denials pass.
- No approval is reusable across a changed SHA, provider config, IAM policy, or key state.
