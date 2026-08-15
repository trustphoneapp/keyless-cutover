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
| Offline bundle/receipt/signature tampering | High | Exact canonical bytes, source hashes/IDs, pinned out-of-band trust anchor | Run the 37 named manifest/artifact/receipt/signature/trust mutations | 37/37 must fail verification |
| Mixed-byte or TOCTOU evidence | Critical | One captured manifest/artifact snapshot per verification; exact raw manifest/receipt binding | Change reader/buffers after capture; mismatch object and bytes | Mixed snapshots cannot verify or promote |
| Historical evidence relabeled as a v3 transaction | Critical claim risk | Require the canonical archive checkpoint to be independently reviewed and merged while the fresh key is enabled; bind all later evidence to it | Attempt to reuse the already-disabled transaction or backfill its archive | Historical evidence remains readiness-only; old key is never re-enabled |
| Local pending output or signature misrepresented as live authority | Critical claim risk | Local issuer remains unrun against an eligible live transaction; no signer exists; pending authorization is immutable; second key cannot replace pinned trust | Wrong key/version/algorithm/digest/signature, valid second-key substitution, and filesafe output races | Signature alone remains `RECOLLECTION_REQUIRED` |
| Forged console success | High | Private authoritative status snapshot; exact state tuple/fields; no local release state | Fabricated/mutated status, stateful accessor, nested Proxy | Reject or serve only the original fail-closed snapshot |
| FIFO or special-file input stalls verification | Medium | Bounded `O_NOFOLLOW`/`O_NONBLOCK` reads plus regular-file `fstat` | FIFO checkpoint and CLI input under kill timeout | Static failure; no hang, fallback, or partial output |
| Audit logs delayed or incomplete | High | Receipt stays pending; target-state proof; source limitations | Disable Data Access/delay logs | Missing evidence cannot become success |
| Disabled key still has issued tokens | Critical claim risk | Test fresh auth only; explicit observation window/wording | Mint token before disable | Never claim universal revocation |
| WIF/IAM propagation delay | Medium | Bounded polling/jitter; no policy weakening | Inject 10–15 minute delay | WAITING/HOLD, no widening |
| Key disable breaks deployment | High | Two canaries before disable; human action; post-disable check; manual rollback | Induce WIF failure after disable | Receipt blocked; human rollback |
| Cancellation/compensation removes preexisting resources | High | `createdByMigration`; semantic ownership; etags | Preexisting identical binding/provider | Never remove unowned resource |
| Repository data sent unnecessarily to model | High | Only workflow + one script + redacted fields; documented retention | Canary PII/secret strings | Secret blocked; minimize PII |

## Security test groups

The passing local suite covers identity/trust failures, stale-state and TOCTOU failures, prompt-injection/malformed-model output, credential leaks, duplicate/replayed/out-of-order events, exact filesystem handling, forged console state, and the fixed 37/37 bundle/receipt/signature mutation matrix. The overall suite count is intentionally not a release claim because it changes as controls are added.

One false-safe result is a release blocker; no majority voting. Local tests do not prove a fresh disposable v3 transaction, its archive-before-disable checkpoint, an authenticated live pending-issuer output, a real scoped KMS signature, or the separate human release decision.
