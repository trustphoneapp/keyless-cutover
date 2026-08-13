# ADR 0001: Freeze a single verified cutover

- Status: accepted
- Date: 2026-08-12

## Context

The broad idea—automatically migrate arbitrary GitHub Actions deployments from long-lived GCP keys to WIF—contains too many workflow, IAM, ownership, and security variants for a 17-day build. A partially simulated or over-broad prototype would create false assurance and score poorly on operational utility and production readiness.

## Decision

Support one `github.com` repository, one direct `auth@v3 credentials_json` deployment job, one repository-scoped secret, one exact GCP user-managed key and existing narrowly scoped deploy service account, and one existing Cloud Run service.

Use WIF through service-account impersonation. Let Keyless create only one fresh provider and exact Workload Identity User binding after digest-bound human approval. Keyless opens but never merges the PR and never manages key state. A separate human disables the exact key only after an authorized canary and eight denials pass.

Use a nonce-bound runner signature for exact key proof, Cloud Run revisions for external action, deterministic authorization oracles, and a KMS-signed scoped receipt.

## Consequences

Positive:

- The full transaction can be real and independently verified.
- Permissions and failure behavior can be exhaustively tested.
- The four-minute demo has a clear before/action/attack/disable/after story.
- Unsupported cases refuse without side effects.

Negative:

- The prototype is not a general enterprise migration product.
- Most real workflow variants are intentionally unsupported.
- A customer-owned executor and IaC integration remain future work.
- Gemini's necessity must be proven through held-out semantic cases, not assumed.

## Revisit criteria

Expand only after the canonical case passes all live, hostile, crash, leak, drift, and receipt gates. Each new workflow family requires its own parser, threat analysis, deterministic compiler path, fixtures, refusal boundary, and live proof.

