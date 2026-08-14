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
- The public evidence console is isolated from the private Taskmaster and has no cloud role, secret, mutation route, or client-side script. Its exact bundle loader rejects special/extra/missing files, and the server renders only a private authoritative snapshot of an internally derived fail-closed status.

## ProofV2 protocol

1. Server writes an `ISSUED` Firestore challenge containing a random 256-bit nonce, issue/expiry time, immutable expected GitHub context, and the selected deployment service account—but not a preselected key ID.
2. A reviewed protected deployment workflow receives the challenge and signs a domain-separated canonical payload using the repository secret in memory.
3. The runner emits only the signed proof; no private material or token is logged or uploaded.
4. The verifier refetches the GitHub run, attempt, workflow path/ref/blob, head SHA, actor ID, triggering-actor login, event, ref, environment, and runner environment.
5. It takes the signed key ID revealed by the protected runner, performs authenticated Google `serviceAccounts.keys.get` under the selected service account, requires that exact active user-managed key, fetches its matching Google X.509 certificate, and verifies signature and expected context.
6. One Firestore transaction rereads `ISSUED` and writes `CONSUMED` plus proof digest. Only that transaction winner succeeds.

The implementation includes payload creation, expected-context equality, lifetime/signature checks, public-certificate lookup, a transactional Firestore challenge store, a completed-run/workflow/review GitHub observer, and an ADC-backed Google key reader. Independently approved run `31758449936` matched the exact active user-managed key, consumed one five-minute Firestore challenge before expiry, rejected replay, and reconstructed the same receipt after consumption.

The WIF readback path compares a canonical hash of the live provider issuer/audiences/mapping/condition to the approved plan, requires the service-account IAM delta to contain exactly one new `roles/iam.workloadIdentityUser` member and no removal, and requires semantic equality of both allowed and forbidden Cloud Run IAM policies across the cutover. This is a scoped “no added downstream permissions” claim, not a universal least-privilege certification.

The live provider/binding read-back matches the approved hashes. `wif-1` deployed through GitHub OIDC, Google STS/WIF, and service-account impersonation. Deterministic collectors independently refetched H1–H8 runs, artifacts, and logs: H1–H6 were rejected by the provider condition, H7 by audience validation, and H8 by Cloud Run IAM. The forbidden service remained on `keyless-forbidden-00001-rvf`.

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
- The recorded already-disabled key predates the mandatory v3 archive checkpoint. Never re-enable it to resume or repair that historical transaction.
- Disabling the key does not revoke tokens minted earlier.
- Post-disable proof uses a fresh hosted runner and a fresh online token/API request; local signing is not authentication proof.
- If WIF fails after disable in a future fresh transaction, only a human may re-enable that fresh key and revert the workflow to restore service; doing so kills the transaction and cannot make it pass later.
- No authenticated pending receipt is issued or presented as release evidence while required live evidence is missing or the key is unexpectedly re-enabled; a signature never replaces the human release boundary.

## External-consumer limitation

Repository scans and activity windows cannot prove that no dormant copy exists elsewhere. In the controlled demo the team owns all consumers. Future customer cases require bounded observations and a human inventory attestation; ambiguity produces `HOLD`.

## Receipt truth

The local v3 verifier captures exact manifest/artifact bytes once and reconstructs only a canonical pending receipt with `RECOLLECTION_REQUIRED` and `release_ready: false`. The current local RC adds authenticated read-only recollection and pending issuance from an exact reviewed/merged checkpoint archive, using a GitHub read token from the environment plus read-only GCP ADC. The filesafe CLI writes one canonical private JSON basename in its current working directory and re-verifies it through the reserved handle. This implementation exists and is tested, but no eligible fresh live transaction or authenticated issuer output exists; it cannot sign or promote a receipt.

A real KMS signature would prove which scoped key signed specific bytes and detect tampering. It would not prove every recorded fact or replace authenticated live recollection. A release receipt must link external GitHub/GCP identifiers, retrieval times, hashes, revisions, policy etags, and limitations so an authorized reviewer can reconstruct the evidence. Live execution of the local issuer and the scoped signature gate remain incomplete.

One false-safe result blocks release.
