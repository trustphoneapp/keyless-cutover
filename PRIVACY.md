# Privacy notice

The hackathon deployment is limited to disposable repositories and GCP projects controlled by the team. It is not intended for personal data or third-party production code.

Keyless reads only the selected workflow, one selected local script when present, immutable repository metadata, normalized GCP identity/configuration metadata, and sanitized execution evidence. It must never retain secret values, private keys, identity/access tokens, or generated credential files.

See [docs/DATA_HANDLING.md](docs/DATA_HANDLING.md) for data boundaries and retention requirements.

