# Local overnight self-review — 2026-08-15

Branch `agent/local-overnight-hardening` reviewed against `origin/main`. Local commits only; nothing pushed. This note does not authorize live K0, secret rotation, workflow dispatch, key disable, KMS signing, or release.

## Scope

Commits `16e1865`…`bbfe9c2` plus the follow-up claim-honesty fix for unused-marker wording.

## Findings

1. **Medium (fixed):** Docs briefly overclaimed that occupied release markers cannot assemble a fresh v3 transaction. Offline verification only enforces pairwise-distinct markers inside one manifest. Docs/tests now state unused markers as an operator/runbook live gate.
2. **No credential leakage** in added evidence; public key IDs and repo metadata only.
3. **No new live authorization path** (no workflow/KMS/dispatch/secret changes that auto-approve sensitive actions).
4. Console, documentation, pin, and compiler tests stay fail-closed (`NO-GO`, `release_ready: false`).

## Local gates run

- Clean-dir `npm ci --legacy-peer-deps --ignore-scripts`, `npm audit --omit=dev --audit-level=high`, full `npm test` → pass (243).
- Independent security subagent review of the branch diff → one medium finding; remediated in this follow-up.

## Remaining human morning work

Leave PR review and live K0 to humans. Do not merge draft marker PR or dispatch baseline from this overnight branch.
