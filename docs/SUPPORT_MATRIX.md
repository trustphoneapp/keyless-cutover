# Supported and rejected workflows

## Supported v1

- Public `github.com` repository created for the hackathon.
- Protected `main` and protected `production` environment with prevent-self-review.
- GitHub-hosted runner.
- One canonical workflow and deployment job.
- Direct `google-github-actions/auth@v3` `credentials_json` usage.
- Inline Cloud Run deploy or exactly one directly referenced local script with statically resolvable literals, one-hop environment bindings, or positional arguments.
- One repository-scoped secret and one unambiguous active user-managed key.
- One GCP project, deploy service account, runtime service account, allowed service, and forbidden service.
- Human-attested controlled consumer inventory.

All third-party actions are pinned to immutable commit SHAs for live evidence.

## Mandatory HOLD/refusal

- Reusable/composite authentication or nested workflow ownership.
- Matrix/dynamic target, generated workflow, arbitrary shell discovery, or multiple local scripts.
- Multiple plausible credentials, keys, service accounts, projects, or targets.
- Organization/environment secret shadowing that cannot be authoritatively ruled out.
- Self-hosted runner, pull-request deployment, mutable-only trust claim, custom audience, or unprotected environment.
- Shared/broad service account, inherited permission ambiguity, or target outside the disposable project.
- Unknown/dormant external consumer risk without human attestation.
- Required API, audit/read-back, reviewer, foreign owner, or protection unavailable.
- Any model-produced resource identity differing from observed/operator-selected scope.
- Incident-response case where immediate containment is required.

## Frozen hostile matrix

| ID | Case | Required rejection point |
|---|---|---|
| H1 | Same workflow under a different numeric owner ID | WIF provider condition |
| H2 | Different numeric repository ID under intended owner | WIF provider condition |
| H3 | Intended repo/workflow from non-`main` ref | WIF provider condition |
| H4 | Intended repo/ref with a different workflow path/ref | WIF provider condition |
| H5 | `workflow_dispatch` instead of allowed `push` | WIF provider condition |
| H6 | `staging` or missing `production` environment | WIF provider condition |
| H7 | Noncanonical audience | STS/provider audience validation |
| H8 | Fully valid WIF identity updates `keyless-forbidden` | Cloud Run resource IAM |

Each row records initiating run ID/attempt/SHA/workflow, intended control, sanitized response category, target revision before/after, and source identifiers. A test that fails before its intended control is `NOT RUN`, not `PASS`.

## Auto-continue gate

Keyless may continue only when all supported facts are independently observed, the plan digest binds their exact values, the effective downstream permission footprint is unchanged, and every required human authority is available.
