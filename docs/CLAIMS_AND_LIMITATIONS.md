# Claims and limitations

## Target release claim — not yet achieved

After all release gates pass, Keyless may claim that it migrated one supported GitHub Actions workflow from one repository-scoped Google service-account JSON secret to a narrowly bound WIF path with no added downstream permissions for one existing Cloud Run service. The target claim includes a human-reviewed PR, one authorized path and eight scoped hostile paths, human disable of the exact key, a fresh legacy authentication failure, post-disable WIF deployment, and a signed scoped receipt.

Today this claim is unproven: there is no live GitHub/GCP K0 evidence, deployed Gemini result, PR, key disable, KMS signature, or hosted demo.

## What the claim requires

- No mocked core integration.
- No hand edit after the generated PR.
- Exact cryptographic key proof.
- Real GitHub OIDC → Google STS → service-account impersonation.
- Real Cloud Run revision changes.
- All eight denials reach their intended controls.
- Human-only key disable.
- Verifiable receipt and tamper failure.

If any condition is absent, use a narrower claim or state that the evidence is pending.

## Honest limitations

- Supports only the exact v1 workflow shape in the support matrix.
- Does not read GitHub secret values through the GitHub API.
- Does not delete the GitHub secret or GCP key.
- Does not guarantee that credentials issued before key disable are invalidated.
- Does not prove security outside the named identities, workflow, service account, resource, and test interval.
- Does not optimize or certify the existing deploy service account's permissions.
- Does not automatically migrate Terraform/Pulumi/CDK-owned identity configuration.
- Does not replace GitHub's official OIDC token, Google's STS/WIF, or the official `google-github-actions/auth` action; those are trusted primitives.
- Does not offer compliance certification, penetration-testing coverage, or multi-tenant production readiness.

## Claim ledger

| Claim | Required evidence | Release blocker |
|---|---|---|
| Exact old key identified | Valid signed probe + matching GCP public key metadata | Yes |
| No privilege widening | Deterministic normalized pre/post permission diff | Yes |
| Authorized WIF works | GitHub run, STS/IAM/Cloud Run evidence, target revision | Yes |
| Hostile path denied | Expected control failure + unchanged target | Yes |
| Key disabled | Live GCP key state + human action reference | Yes |
| Fresh old-key auth fails | New post-disable authentication attempt | Yes |
| WIF continuity | Fresh post-disable WIF deployment and revision | Yes |
| Receipt authentic | KMS signature verifies; tampered copy fails | Yes |
| Gemini is necessary | Held-out ablation beats rules baseline by threshold | Required for agentic claim, not core utility |

## Forbidden marketing language

Avoid: “fully secure,” “fully keyless,” “all attacks blocked,” “safe to delete,” “key revoked,” “zero downtime,” “enterprise compliant,” “one-click rollback,” and “autonomous IAM.”

Prefer scoped, observable wording from the receipt.
