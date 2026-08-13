# Gemini and ADK boundary

> ADR 0002 removes the Plan Agent. Gemini v1 is limited to sourced evidence interpretation and bounded recovery diagnosis; deterministic code owns every policy and patch.

## Why Gemini exists

The model is justified only for variable repository semantics and compound failure diagnosis:

- Trace authentication intent across workflow structure and one referenced local script.
- Distinguish the GCP service-account credential from unrelated API/signing/publishing secrets.
- Explain how the existing workflow authenticates and deploys.
- Emit sourced candidate facts in a typed `MigrationIR`.
- Correlate GitHub, IAM, STS, Cloud Run, and audit evidence after a failed canary.
- Propose one bounded recovery option for deterministic revalidation.

## ADK stages

```text
Evidence Agent
  → Plan Agent
  → Deterministic verifier/compiler
  → State controller
  → Recovery Agent when an external proof fails
```

The ADK graph must be on the served path and visible in traces. It is not a decorative diagram.

## Model inputs

Allowed:

- Workflow AST and bounded source spans.
- One directly referenced local script after redaction.
- Repository numeric/display identity.
- Secret names and scopes, never values.
- Normalized IAM roles/resource names.
- Sanitized GitHub run metadata and bounded log excerpts.
- Sanitized error codes and audit observations.

Prohibited:

- Service-account JSON/private key.
- GitHub App/install/OAuth tokens.
- OIDC JWT or Google access/ID tokens.
- Authorization headers.
- Raw environment dumps.
- Unbounded repository contents or complete audit payloads.

## Model outputs

The model emits a strict typed structure containing:

- Candidate legacy authentication evidence with source spans.
- Candidate deployment intent and target.
- Supported/unsupported pattern classification.
- Proposed identity constraints as semantic fields, not CEL strings.
- Risk findings and missing evidence.
- Recovery hypothesis from allowlisted categories.

Unknown fields, free-form executable code, shell commands, roles, or arbitrary resource identifiers fail schema validation.

## Deterministic ownership

Only deterministic code may:

- Construct CEL.
- Choose allowed roles/resources from frozen configuration.
- Compare effective permissions.
- Decide PASS/HOLD/DENY.
- Apply a state transition.
- Call mutation APIs.
- Judge canary/denial results.
- Validate key state.
- Complete/sign a receipt.

## Prompt-injection design

- Repository bytes are explicitly marked untrusted evidence.
- Comments and prose are removed from authorization inputs.
- Model receives no mutation tool definitions or credentials.
- Model output is parsed as data, never executed.
- The compiler generates final workflow/IAM artifacts from validated scalars.
- Injection corpus includes direct, encoded, Unicode, log-based, YAML-key, comment, and dependency instructions.

## Necessity test

Compare:

1. Fixed canonical template.
2. Rules-only YAML/parser engine.
3. Full Gemini + deterministic engine.

On eight held-out supported semantic cases, full Keyless must improve safe-success by at least 25 percentage points over rules-only without increasing unsafe migrations. It must also reach at least 85% top-one diagnosis accuracy on 20 injected multi-artifact failures.

If these thresholds fail, remove or reposition the model; do not claim agentic necessity.
