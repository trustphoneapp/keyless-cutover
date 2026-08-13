# Security model

## Core invariant

Keyless may help remove one permanent authentication path only when it can prove the exact reviewed scope, preserve downstream permissions, test intended and hostile identities, and stop before any uncertain or irreversible boundary.

## Trust boundaries

- Repository YAML, scripts, comments, logs, issues, and model output are untrusted.
- Private keys and OIDC/access tokens exist only inside their authorized runner/tool boundary and never enter Keyless storage or Gemini.
- Deterministic code—not the model—owns identities, policy, authorization verdicts, patch bytes, and receipt completeness.
- GitHub protection and independent review own merge authority.
- A human owns IAM application and key disable.
- Google and GitHub source state outranks Keyless’s database.

## ProofV2 protocol

1. Server writes an `ISSUED` Firestore challenge containing a random 256-bit nonce, issue/expiry time, immutable expected GitHub context, and selected Google key scope.
2. A reviewed protected deployment workflow receives the challenge and signs a domain-separated canonical payload using the repository secret in memory.
3. The runner emits only the signed proof; no private material or token is logged or uploaded.
4. The verifier refetches the GitHub run, attempt, workflow path/ref/blob, head SHA, actor ID, triggering-actor login, event, ref, environment, and runner environment.
5. It performs authenticated Google `serviceAccounts.keys.get`, requires the exact active user-managed key, fetches the matching Google X.509 certificate, and verifies signature and expected context.
6. One Firestore transaction rereads `ISSUED` and writes `CONSUMED` plus proof digest. Only that transaction winner succeeds.

The current local module implements only payload creation, expected-context equality, lifetime, signature, and public-certificate lookup. It does not yet implement this complete protocol.

## Mandatory identity tests

H1–H7 must reach STS/provider or impersonation as specified; H8 must reach Cloud Run authorization. Client syntax failure, missing approval, network failure, cancellation, or absent logs is `NOT RUN`.

STS client errors may not appear in audit logs. A denial therefore requires a pinned reviewed probe’s sanitized response plus evidence that no credential/target mutation occurred. Absence of an audit log is never proof.

## Permissions

- Taskmaster: read selected repository/evidence, call Vertex, write Firestore state, and open compiler-owned draft PR only.
- Taskmaster: no IAM mutation, Cloud Run deploy, key admin, PR merge, shell execution, or secret-value access.
- WIF principal: `roles/iam.workloadIdentityUser` on one deployment service account.
- Deployment service account: exact allowed Cloud Run service update/read and exact runtime-service-account act-as permissions; no forbidden service access.
- Human IAM operator: temporary disposable-project permissions to apply the reviewed provider/binding.
- Human key operator: exact key get/list/disable authority; no automatic deletion.

## Prompt injection

Gemini input is redacted and bounded. Model outputs contain cited source spans, fixed enums, missing evidence, and diagnosis only. Any resource identifier is ignored unless it exactly equals independently observed scope. The model cannot call mutation tools or emit free-form CEL, IAM roles, shell, or patches.

## Disable and rollback truth

- Disable, do not delete. Disable is reversible.
- Disabling the key does not revoke tokens minted earlier.
- Post-disable proof uses a fresh hosted runner and a fresh online token/API request; local signing is not authentication proof.
- If WIF fails after disable, only a human may re-enable the exact key and revert the workflow.
- No final receipt is issued while required evidence is pending or the key is unexpectedly re-enabled.

## External-consumer limitation

Repository scans and activity windows cannot prove that no dormant copy exists elsewhere. In the controlled demo the team owns all consumers. Future customer cases require bounded observations and a human inventory attestation; ambiguity produces `HOLD`.

## Receipt truth

A KMS signature proves which Keyless key signed specific bytes and detects tampering. It does not prove every recorded fact. A final receipt must link external GitHub/GCP identifiers, retrieval times, hashes, revisions, policy etags, and limitations so an authorized reviewer can reconstruct the evidence.

One false-safe result blocks release.
