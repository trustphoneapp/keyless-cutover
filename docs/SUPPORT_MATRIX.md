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

## Executable mapping

- H1: copy `k0/templates/k0-external-hostile.yml` to the canonical workflow path in the independent human's repository and push `demo/release.txt` on `main`.
- H2: copy the same frozen template to a second repository owned by the intended owner and push `demo/release.txt` on `main`.
- H3: push only `demo/release.txt` to the fixed `keyless-h3` branch. The canonical workflow's `h3-wrong-ref` job runs.
- H4: push `demo/release.txt` on `main`; `.github/workflows/k0-hostile-wrong-workflow.yml` runs beside the authorized workflow.
- H5: manually dispatch the canonical workflow from `main`; only `h5-wrong-event` is eligible.
- H6/H7/H8: every canonical `main` release push runs fixed wrong-environment, wrong-audience, and forbidden-resource jobs beside the authorized deploy.

Expected-denial steps use `continue-on-error` only to allow an exact subsequent assertion that the authentication or forbidden mutation step failed. That assertion emits a seven-day, credential-free artifact containing the platform run ID/attempt/SHA/workflow/ref/event/environment and failed step outcome. A green hostile job plus its artifact is still insufficient alone: the run log and independently read target revision are required. Missing environment approval, an unexecuted step, syntax failure, or an earlier network failure cannot satisfy the K0 manifest.

The collector independently refetches the completed GitHub run and named job, downloads the exact artifact and job log through trusted redirect hosts without forwarding authorization, and binds their immutable IDs. It recognizes only bounded Google rejection signatures: WIF attribute-condition rejection for H1–H6, audience rejection at the Google auth/STS path for H7, and Cloud Run update permission denial for H8. The sanitized evidence records the raw log digest but does not retain the raw log. Unrecognized text is `NOT PROVEN`, never a denial.

## Auto-continue gate

Keyless may continue only when all supported facts are independently observed, the plan digest binds their exact values, the effective downstream permission footprint is unchanged, and every required human authority is available.
