# Threat model

> Current actors and human-IAM boundaries are defined by `SECURITY_MODEL.md` and ADR 0002. Conflicting autonomous-worker assumptions below are historical.

## Severity model

- **Critical:** can expose credentials, grant unintended cloud access, disable the wrong key, or falsify a receipt.
- **High:** can corrupt approval, evidence, tenant isolation, or availability.
- **Medium:** bounded availability, propagation, or evidence-quality failure.

## Threat register

| Threat | Sev. | Control | Verification | Ship rule |
|---|---|---|---|---|
| Prompt injection in YAML/log/script | Critical | Treat as quoted evidence; redaction; typed model output; no model mutation tools; deterministic compiler | Direct/encoded/Unicode/comment/log injection corpus | Block if model can cross mutation boundary |
| Shared GitHub OIDC issuer/confused deputy | Critical | Numeric owner/repo IDs; exact ref/workflow/environment/event/audience | Wrong owner/repo/name-reuse tests | Any success blocks release |
| Repository rename/transfer | Critical | Numeric IDs; fresh OIDC claim observation; transfer invalidates approval | Rename/transfer fixture | Name-only trust prohibited |
| Wrong audience/issuer | Critical | Exact issuer and provider-resource audience | Wrong/missing/case-variant audience | Real denial required |
| Fork/PR or `pull_request_target` executes privileged code | Critical | Push-to-protected-main only; protected environment; no PR deployment | Fork/PR/PR-target tests | Unsupported or denied |
| Broad impersonation grant | Critical | Exact principal on one service account; no project/folder Token Creator | Try second service account | Any lateral impersonation blocks |
| Privilege widening in generated plan | Critical | Normalized before/after permission diff; role/resource allowlist | Owner/Editor/wildcard/multi-resource mutations | Zero widening allowed |
| Signed probe leaks key | Critical | In-memory Node crypto; no shell tracing; only metadata/signature; leak scan | PEM/base64/high-entropy scans of all outputs | Any private material kills project |
| Wrong key correlation | Critical | Nonce-bound signature verified with GCP public key; immutable repo/workflow/run binding | Multiple similar keys, stale nonce, wrong key | Ambiguity means HOLD |
| Positive canary succeeds via ambient/old credentials | Critical | Fresh GitHub-hosted runner; remove alternate auth; verify federated principal and exact revision | Seed ambient credential fixture | Identity provenance required |
| Fake or insufficient negative test | Critical | Expected enforcement-point assertion and unchanged target | Network/syntax/unrunnable identity cases | `NOT RUN` is never PASS |
| Stale approval/TOCTOU | Critical | Digest binds SHA, IAM etag, provider, key, target, compiler; immediate recheck | Mutate each bound value | Any change invalidates |
| Keyless worker compromise | Critical | Disposable allowlisted project; additive WIF only; no key/deploy/admin permissions | IAM permission audit | Excess scope kills release |
| GitHub App compromise | Critical | Selected repo; minimal permissions; Secret Manager; rotation; installation-token scope | Cross-repo access attempt | Cross-repo access blocks |
| Credential file enters artifact/image | Critical | Authenticate after build; ignore/delete `gha-creds-*`; scan artifacts | Tar/build/upload workspace after auth | Any credential artifact blocks |
| Third-party action compromise | Critical | Pin privileged actions to full SHA; owner allowlist | Mutable tag substitution test | Mutable refs prohibited |
| Workflow/log content forges success | High | Never trust stdout; query GitHub/GCP target/audit state | Print fake success with failed deployment | Self-attestation cannot pass |
| Duplicate/replayed webhook/task | High | HMAC; delivery dedupe; deterministic task/operation IDs; CAS | Duplicate/reorder/replay matrix | One semantic effect only |
| IAM concurrent modification | High | Version-3 policy+etag; normalized preimage; fail on drift | Unrelated concurrent binding | No lost update/rebase |
| Cross-tenant object reference | Critical | Single-tenant demo; installation/repo/project IDs on every object | IDOR/fuzz tests | Multi-tenant claim prohibited |
| Receipt tampering | High | Canonical JSON + Cloud KMS signature; source hashes/IDs | Modify 20 fields/files | 20/20 must fail verification |
| Audit logs delayed or incomplete | High | Receipt stays pending; target-state proof; source limitations | Disable Data Access/delay logs | Missing evidence cannot become success |
| Disabled key still has issued tokens | Critical claim risk | Test fresh auth only; explicit observation window/wording | Mint token before disable | Never claim universal revocation |
| WIF/IAM propagation delay | Medium | Bounded polling/jitter; no policy weakening | Inject 10–15 minute delay | WAITING/HOLD, no widening |
| Key disable breaks deployment | High | Two canaries before disable; human action; post-disable check; manual rollback | Induce WIF failure after disable | Receipt blocked; human rollback |
| Cancellation/compensation removes preexisting resources | High | `createdByMigration`; semantic ownership; etags | Preexisting identical binding/provider | Never remove unowned resource |
| Repository data sent unnecessarily to model | High | Only workflow + one script + redacted fields; documented retention | Canary PII/secret strings | Secret blocked; minimize PII |

## Security test groups

The minimum 25-test release suite contains:

- Eight identity/trust failures.
- Five stale-state/TOCTOU failures.
- Four prompt-injection or malformed-model outputs.
- Three credential-leak tests.
- Three duplicate/replayed/out-of-order event tests.
- Two receipt-tampering tests.

One false-safe result is a release blocker; no majority voting.
