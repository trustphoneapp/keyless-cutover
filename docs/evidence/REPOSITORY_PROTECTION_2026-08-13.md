# Public repository and protection evidence — 2026-08-13

Observed at `2026-08-13T20:12:55Z` through live GitHub API read-back.

## Repository state

- Repository: `trustphoneapp/keyless-cutover`
- Visibility: `PUBLIC`
- Default branch: `main`
- GitHub secret-scanning alerts: `0`
- Independent collaborator: `cherala2002`, accepted with repository `write` access

## Credential-history scan

Gitleaks `8.30.1` scanned all 48 reachable commits and approximately 638 KB of Git history with full output redaction. It returned four `generic-api-key` pattern findings in documentation, source-validation code, and test fixtures. A separate high-risk shape check over the exact historical lines found no private-key header, GitHub token, Google access/API token, AWS access key, or Google browser authorization-code shape. No credential value is reproduced in this record.

These four generic matches remain recorded as false-positive candidates rather than being silently discarded. The final clean-release scan must rerun after the last commit and independently review any finding before submission.

## Protected `main`

- Required status check: `test`
- Branch must be current with `main` before merge
- Required approvals: `1`
- Last pusher cannot supply the required approval
- Stale approvals are dismissed after a new push
- Administrators are subject to protection
- Conversations must be resolved
- Force pushes and branch deletion are disabled

## Protected `production`

- Required reviewer: `cherala2002`
- Self-review is prevented
- Administrator bypass is disabled
- Deployments are limited to protected branches

## Release-candidate observation

PR #11 head `a26899e78c34ee31c019c4a29550feea273945bc` had a successful `test` check and GitHub reported `REVIEW_REQUIRED` / `BLOCKED`. That is the intended fail-closed state before the independent collaborator approves the exact final head.
