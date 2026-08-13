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

