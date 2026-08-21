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
  → Deterministic verifier/compiler
  → Recovery Agent when an external proof fails
```

Both agents use `gemini-3.5-flash`, have no tools or transfer routes, and emit strict Zod outputs. The Evidence stage runs before deterministic compilation. Recovery runs only on an allowlisted failed observation. The ADK path is served privately from Cloud Run; a real dual-authenticated Vertex invocation and the second 72-call sealed evaluation passed. Final release still requires an independent hash-held rerun.

## Model inputs

Allowed:

- Bounded redacted workflow evidence spans.
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
- Supported/unsupported pattern classification.
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
- Injection corpus (`eval/cases.mjs`) currently contains two plaintext comment-injection cases (D-E04, S-F01), scored deterministically via `PROMPT_INJECTION_TEXT`; encoded, Unicode, log-based, YAML-key, and dependency variants are not yet covered.

## Necessity test

Compare:

1. Fixed canonical template.
2. Rules-only YAML/parser engine.
3. Direct one-shot Gemini.
4. ADK Evidence plus conditional Recovery agents followed by the same deterministic compiler.
5. ADK path with Recovery disabled.

The 36-case corpus contains 12 visible development cases, 12 sealed supported cases, 4 sealed refusal cases, and 8 sealed recovery cases. Release requires at least 10/12 supported successes, at least 3/12 paired wins over rules-only, 4/4 refusals, at least 7/8 top-one recovery diagnoses, and zero forbidden output or false-safe result. Deterministic oracles—not an LLM judge—score every security gate.

If these thresholds fail, the agentic premise fails and the project pivots; mandatory model use will not be made decorative.
