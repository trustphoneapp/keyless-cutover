# Served API contract

The hackathon service is intentionally not a broad migration control plane. It exposes two bounded model routes on one private Cloud Run service. GitHub observation, deterministic compilation, evidence collection, IAM application, merge, and key disable remain outside the model API.

## Authentication

Cloud Run IAM authenticates an allowlisted invoke-only operator identity. Model routes then require a separate `X-Keyless-API-Token` application header whose value is stored in Secret Manager. The application token is not accepted in `Authorization`, because Cloud Run reserves that header for its own identity token.

Neither credential may be logged, persisted, placed in an evidence bundle, or sent to Gemini. IAM alone reaches the application but receives `401` from a model route when the application header is absent.

## Routes

### `GET /healthz`

Returns the fixed service/model/tool status used by the container startup probe. The production service remains private, and this route does not establish that Gemini was invoked.

### `POST /v1/evidence`

Accepts exactly one JSON object containing `evidence`: 1–20 `{id,text}` items, at most 8,000 characters each and 32,000 total. IDs must match `E###`; duplicate IDs, unknown fields, oversized input, and credential-shaped material are rejected.

The tool-free ADK Evidence Agent returns only the strict candidate classification, known evidence references, allowlisted missing-evidence/risk codes, and a bounded explanation. The server revalidates every citation against the submitted bundle.

### `POST /v1/recovery`

Accepts the same redacted evidence envelope. The tool-free ADK Recovery Agent returns one allowlisted failure category, cited evidence, a typed expected/observed mismatch, one next observation, and a bounded explanation. It cannot retry, mutate, authorize, or declare success.

## Responses

- `200 {"output": ...}` only after strict final validation.
- `400 {"error":"request_rejected"}` for invalid input, invalid model output, or failed invocation. Provider details are not reflected.
- `401 {"error":"unauthorized"}` when the application token is absent or wrong.
- `404 {"error":"not_found"}` for unsupported methods or paths.

Request bodies are capped at 64 KiB. Unknown output fields, invented citations, executable content outside the schemas, and credential-shaped input fail closed.

## Deliberate exclusions

There is no public `/migrations`, webhook, approval, worker, IAM, key, merge, receipt-finalization, or arbitrary-chat endpoint. The v1 Taskmaster uses existing deterministic CLI/adapters and human gates for those responsibilities. Cloud Tasks, Pub/Sub, autonomous IAM, and generic multi-tenant APIs remain out of scope.

The exact implementation is in `agent/server.mjs`, `agent/contracts.mjs`, and `agent/invoke.mjs`; tests exercise dual authentication, schema rejection, and citation binding.
