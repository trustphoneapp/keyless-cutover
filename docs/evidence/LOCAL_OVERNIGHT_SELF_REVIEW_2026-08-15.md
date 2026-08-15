# Local overnight self-review — 2026-08-15

Branch `agent/local-overnight-hardening` reviewed against `origin/main`. Local commits only; nothing pushed. This note does not authorize live K0, secret rotation, workflow dispatch, key disable, KMS signing, or release.

## Scope

Commits from `16e1865` through tip on this branch (local overnight hardening loop). Full suite last green at **276** tests.

## Findings remediations already landed

1. Unused-marker overclaim softened to operator/runbook gate (not offline denylist).
2. Eval scorer treats credential-shaped and incomplete attempt sets as forbidden.
3. Console HTML requires fail-closed status tuples; refuses `GO`/`AUTHORIZED` headlines.
4. Credential inventory covers `bin/`, `k0/`, `.github/`, and `docs/evidence`.
5. Firestore ISSUED/CONSUMED exact RFC3339 field sets; GitHub write-token denylist; key-proof Zulu times.
6. ProofV2 issue requires `workflow_dispatch` / `main` / `production`.
7. Evidence/artifact `github_pat` + duplicate-key refuse; bundle `O_NOFOLLOW`; CI/package script locks.
8. Google key Content-Length match; draft PR refuses non-draft/merged responses; agent invoker credential/duplicate refuse.
9. Receipt scope exact fields; bundle/eval-score/assemble JSON gates; workflow snapshot credential/multiline refuse.
10. Shared `rejectDuplicateJsonKeys` across GitHub evidence collectors.
11. Canary method/path allowlist; legacy Google key identity/Content-Length parity.
12. Console duplicate-JSON + numeric ProofV2 run_id; bounded-file hardlink/size integrity.
13. Normalizers bind key names/project patterns; Cloud Run digests; ProofV2 CLI; eval basename docs.
14. Console GET-only 405; frozen KMS signing requests; refuse Bearer/whitespace GitHub tokens.
15. Credential scan AKIA/Slack; distinct live-issuer run IDs; demo Dockerfile /healthz HEALTHCHECK.
16. Firestore event_name/environment allowlists; rejectDuplicateJsonKeys unit coverage.
17. Agent/console HEALTHCHECK; draft-PR duplicate JSON; evidence AKIA/Slack; receipt duplicate keys.

## Hard stops held

No `gh`, push, merge, dispatch, secrets, keys, KMS, Cloud Agents, or reviewer pings.

## Remaining human morning work

Leave PR review and live K0 to humans. Do not merge draft marker PR or dispatch baseline from this overnight branch.
