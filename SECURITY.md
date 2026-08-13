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

The lockfile pins `@google/adk` 1.6.0. As of August 13, 2026, `npm audit --omit=dev` reports 19 moderate transitive advisories in its Google/OpenTelemetry dependency graph and no high or critical advisories. CI fails on any high or critical advisory. Do not use `npm audit fix --force`: its proposed repair downgrades ADK across a breaking boundary. Model prompt/response logging must remain disabled; evidence content must not be exported through telemetry.
