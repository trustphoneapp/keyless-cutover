# Local overnight self-review — 2026-08-15

Branch `agent/local-overnight-hardening` reviewed against `origin/main`. Local commits only; nothing pushed. This note does not authorize live K0, secret rotation, workflow dispatch, key disable, KMS signing, or release.

## Scope

Commits from `16e1865` through tip on this branch (local overnight hardening loop). Full suite last green at **258** tests.

## Findings remediations already landed

1. Unused-marker overclaim softened to operator/runbook gate (not offline denylist).
2. Eval scorer treats credential-shaped and incomplete attempt sets as forbidden.
3. Console HTML requires fail-closed status tuples; refuses `GO`/`AUTHORIZED` headlines.
4. Credential inventory covers `bin/`, `k0/`, `.github/`, and `docs/evidence`.
5. Firestore ISSUED/CONSUMED exact RFC3339 field sets; GitHub write-token denylist; key-proof Zulu times.
6. ProofV2 issue requires `workflow_dispatch` / `main` / `production`.
7. Evidence/artifact `github_pat` + duplicate-key refuse; bundle `O_NOFOLLOW`; CI/package script locks.
8. Google key Content-Length match; draft PR refuses non-draft/merged responses; agent invoker credential/duplicate refuse.

## Hard stops held

No `gh`, push, merge, dispatch, secrets, keys, KMS, Cloud Agents, or reviewer pings.

## Remaining human morning work

Leave PR review and live K0 to humans. Do not merge draft marker PR or dispatch baseline from this overnight branch.
