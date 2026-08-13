# Security policy

Keyless Cutover is a hackathon prototype and is not approved for production credentials or customer infrastructure.

## Reporting

Do not open a public issue containing credentials, tokens, private repository content, or exploit details. Contact the repository owner privately and include only sanitized reproduction information.

## Supported security scope

Only the exact v1 case in [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) is evaluated. Unsupported configurations must enter `HOLD` without mutation.

## Immediate stop conditions

- Any credential value reaches logs, storage, artifacts, model input, or receipts.
- Any hostile identity reaches the protected target.
- The worker can manage service-account keys or merge its PR.
- IAM privilege widens or an approval can be replayed after drift.
- A receipt can be tampered with and still verify.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Dependency gate

The lockfile pins `@google/adk` 1.6.0. As of August 13, 2026, `npm audit --omit=dev --audit-level=high` reports zero known vulnerabilities. CI installs the exact lockfile with lifecycle scripts disabled and fails on any high or critical advisory. ADK 1.6.0 publishes five MikroORM database drivers as required peers even though Keyless uses only `InMemoryRunner`; the release preflight permits exactly those five missing drivers and fails on every other missing, invalid, or extraneous dependency. The final runtime image contains neither npm nor Corepack, and both arm64 and Cloud Run's amd64 image builds scanned at zero critical/high findings. Do not use `npm audit fix --force`. Model prompt/response logging must remain disabled; evidence content must not be exported through telemetry.

The agent HTTP routes require a bearer secret of at least 256 bits; only `/healthz` is public. Store the token in Secret Manager at deployment, never in the image or repository. The service rejects bodies over 64 KiB and the model contract further caps evidence text at 32,000 characters.
