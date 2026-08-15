# Public repository and protection evidence — 2026-08-15

Observed at `2026-08-15T06:02:22Z` through live GitHub API read-back. This record completes the C3 protection-tuple read-back after PRs #18 and #19. It does not authorize a live K0 transaction, secret rotation, workflow dispatch, key disable, KMS signing, or release.

## Repository state

- Repository: `trustphoneapp/keyless-cutover`
- Visibility: `PUBLIC`
- Default branch: `main`
- Head: `6ac7c78e34cc6a3ba170dc217cd1a737cd44e30d` (`Prepare fresh K0 legacy baseline (#19)`)
- Owner ID: `289479481`
- Repository ID: `1332803088`
- Independent collaborator: `cherala2002` (`214124322`), repository `write`

## Protected `main`

Read back from `GET /repos/trustphoneapp/keyless-cutover/branches/main/protection`:

- Required status check: `test`
- Required checks are strict (`branch must be current with main`)
- Required approvals: `1`
- Last pusher cannot supply the required approval
- Stale approvals are dismissed after a new push
- Administrators are subject to protection
- Conversations must be resolved
- Force pushes and branch deletion are disabled
- `required_linear_history.enabled`: `true`

## Protected `production`

Read back from `GET /repos/trustphoneapp/keyless-cutover/environments/production`:

- Required reviewer: `cherala2002`
- Self-review is prevented
- Administrator bypass is disabled
- Deployments are limited to protected branches

## Merged release-candidate evidence

- PR #18 `Complete fail-closed K0 evidence pipeline` merged `2026-08-14T23:54:21Z` as `15b7cb5ef0c7e09ce631519e27fddb7209ff4c31`. Independent review by `cherala2002` applied to `c313beb9d8d02735c2b73b53f0036fd2ce8923ed`. Required `test` check was green. The review explicitly did not authorize live K0 execution, KMS signing, or release.
- PR #19 `Prepare fresh K0 legacy baseline` merged `2026-08-15T05:44:30Z` as `6ac7c78e34cc6a3ba170dc217cd1a737cd44e30d`. Independent review by `cherala2002` applied to `f6f79482fcac00ae4a9d1c748a2928b87be7b89a`. The review authorized merge only.

## Canonical legacy-baseline workflow

On `main` at the observation time, `.github/workflows/k0-deploy.yml` is byte-identical to `k0/templates/k0-deploy.legacy.yml`:

- SHA-256: `efa494890963b2744b031a54f78f13df5575b948eec9fa2ec452342fda6feebf`
- Git blob: `62ec226833a2ac44913044ab665a01b0f0f271db`
- Trigger: `workflow_dispatch` only
- Job predicate: `vars.KEYLESS_K0_ENABLED == 'true' && github.ref == 'refs/heads/main'`
- Repository variable `KEYLESS_K0_ENABLED` value: `true`

## Operational inventory — not v3 completion

- Historical user-managed key `253d40858619a76541f1b6374d157560cf8b14f6` remains disabled with `SERVICE_ACCOUNT_KEY_DISABLE_REASON_USER_INITIATED`.
- Fresh user-managed key `1f0137c50d534e23c58e2ae0f84ccf3a9847351d` exists on `keyless-deploy@keyless-k0-20260813.iam.gserviceaccount.com`, `validAfterTime` `2026-08-14T23:59:58Z`, and is enabled. Repository variable `GCP_LEGACY_KEY_ID` names this key.
- `demo/release.txt` is still `wif-1`. Cloud Run already has revisions `keyless-demo-legacy-1` and `keyless-demo-wif-1`. A fresh baseline must use an unused marker. Changing `demo/release.txt` on `main` starts `.github/workflows/k0-hostile-wrong-workflow.yml` (H4) because `KEYLESS_K0_ENABLED` is `true`.
- Whether `secrets.GCP_SERVICE_ACCOUNT_KEY` matches the fresh key was not observed. GitHub secret values are never read back.
- No live K0 workflow_dispatch has run against this head. The 48-hour kill gate has not started.

## Stop conditions still in force

Do not re-enable the historical key. Do not dispatch the legacy baseline until an unused release marker is merged and the operator independently confirms the secret’s `private_key_id`. Do not treat this file as a completed v3 receipt.
