# Claims and limitations

## Target release claim — pre-disable half achieved, continuity structurally blocked

After all release gates pass, Keyless may claim that it migrated one supported GitHub Actions workflow from one repository-scoped Google service-account JSON secret to a narrowly bound WIF path with no added downstream permissions for one existing Cloud Run service. The target claim includes a human-reviewed PR, one authorized path and eight scoped hostile paths, an independently reviewed canonical archive checkpoint completed while the fresh key remained enabled, human disable of that exact key, a fresh legacy authentication failure before post-disable WIF deployment, authenticated issuance of the exact pending receipt, a scoped real signature verified against pinned trust, and a separate human release decision. The signature does not itself authorize release.

The 2026-08-24 fresh transaction proved the archive-before-disable half of this claim on real GitHub and Google state: fresh `legacy-3`, ProofV2 run `32761994628`, the compiler-owned WIF cutover, `wif-3`, all eight hostile denials, the canonical pre-disable archive checkpoint reviewed and merged with its check and push run both completing before disable, the human key disable, and a fresh legacy authentication failure afterward. See [README.md](../README.md)'s "The fresh transaction" section for exact run IDs and timestamps.

Continuity — a fresh post-disable `wif-2` deployment — was not achieved, and live testing found it structurally blocked on this repository rather than merely undone: the hostile jobs sharing `deploy`'s trigger always add extra Cloud Audit Log entries to the post-disable window, and the only fix changes the workflow's bytes, which breaks the separate requirement that a post-disable run's bytes match what `wif-1` used. A fresh key cannot route around this either, because a fresh `legacy_baseline` can never be collected again after the one-time cutover merges. Authenticated pending issuance and the scoped KMS signature were correctly not attempted, since both require `post_disable` evidence that cannot exist for this transaction; the manifest remains `RECOLLECTION_REQUIRED` with `release_ready: false`. The overall claim therefore remains unproven, for a now-understood structural reason rather than a remaining task.

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
| Pre-disable transaction checkpointed | Exact canonical archive independently reviewed, merged, and reread while the fresh key remains enabled | Yes |
| Key disabled | Live GCP key state + human action reference | Yes |
| Fresh old-key auth fails | New post-disable authentication attempt | Yes |
| WIF continuity | Fresh post-disable WIF deployment and revision | Yes |
| Receipt authentic | Authenticated live recollection issues the exact pending receipt; the scoped real KMS signature verifies against pinned out-of-band trust and tampered bytes fail | Yes |
| Gemini is necessary | Held-out ablation beats rules baseline by threshold | Required for agentic claim, not core utility |

As of 2026-08-24: "Exact old key identified", "No privilege widening", "Authorized WIF works", "Hostile path denied", "Key disabled", and "Fresh old-key auth fails" are met. "Pre-disable transaction checkpointed" is only partially met: the archive was independently reviewed and merged before disable, but its "reread" component runs inside the pending issuer, which never ran — the same block that stops "WIF continuity" and "Receipt authentic" from being met.

## Forbidden marketing language

Avoid: “fully secure,” “fully keyless,” “all attacks blocked,” “safe to delete,” “key revoked,” “zero downtime,” “enterprise compliant,” “one-click rollback,” and “autonomous IAM.”

Prefer scoped, observable wording from the receipt.
