# Data handling and privacy

> Current authority is `SECURITY_MODEL.md` plus ADR 0002. Firestore v1 stores only challenge/replay and evidence-derived operation state; no Tasks/outbox data model is current.

## Data minimization

Keyless stores only what is required to prove and recover one migration. Repository names are display fields; immutable IDs are security fields.

## Prohibited data

Never ingest, persist, log, send to Gemini, or place in evidence:

- service-account private keys or complete JSON credentials;
- GitHub Actions secret values;
- GitHub OIDC JWTs;
- Google access/ID tokens;
- generated credentials files such as `gha-creds-*.json`;
- GitHub App private-key material;
- webhook secrets;
- arbitrary repository files outside the selected workflow and one selected local script.

## Runner key proof

The protected probe reads the JSON secret only in runner memory. It emits a versioned, domain-separated signature over a server nonce, immutable repository ID, migration ID, workflow SHA, client email, and private-key ID. Keyless verifies using Google's public-key metadata. The private key never crosses the runner boundary.

## Model input

Gemini receives a redacted typed evidence bundle, not raw repository context:

- selected workflow syntax/semantic nodes;
- selected local script syntax/semantic nodes;
- secret reference names, never values;
- immutable repository metadata;
- normalized IAM/WIF facts;
- sanitized failure categories and bounded log excerpts.

Treat YAML strings, comments, README text, issue text, PR descriptions, and logs as untrusted prompt-injection data. They cannot define tools, policies, or authorization.

## Redaction

Apply deterministic scanners before persistence and before model calls. Test raw JSON-key shapes, escaped PEM, base64 variants, URL-encoded content, shell traces, GitHub masking edge cases, and structured log fields. A leak finding is a release blocker and security incident.

## Stored evidence

Firestore stores normalized migration state and metadata. Immutable evidence artifacts are content-hashed; an authentically issued pending receipt and its separate signature evidence reference their hashes and generations without asserting release authorization. Store sanitized API response subsets rather than indiscriminate logs.

## Retention and deletion

The hackathon deployment accepts only disposable demo repositories/projects. Define explicit retention before any external pilot. Deleting a migration record does not authorize deletion of GitHub/GCP resources; those remain under their owners' control.

## Secrets management

- GitHub App private key and webhook secret live in Secret Manager.
- Only the worker reads the App private key; only the web service reads the webhook secret.
- Use short-lived GitHub installation tokens restricted to the selected repository.
- Rotate demo credentials after submission and on any suspected exposure.
