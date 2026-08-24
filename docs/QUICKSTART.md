# Developer quickstart

This quickstart validates the public source without granting cloud authority or replaying the live disposable cutover. The final live-operator setup remains gated by K0 and `REVIEWER_RUNBOOK.md`.

## Requirements

- Node.js 22 or newer.
- Git.
- `gh` and `gcloud` only for authorized live operators; local tests do not need cloud credentials.

## Validate a clean checkout

```sh
npm ci --legacy-peer-deps --ignore-scripts
npm test
npm audit --omit=dev --audit-level=high
```

The current local suite passes and the dependency audit is enforced at the configured threshold without publishing a brittle test count. The suite also fails on unreviewed dependency-tree problems, unpinned workflow actions, an unpinned ProofV2 runtime, hidden proof-artifact paths, package-manager tooling in runtime containers, absent/self environment review, ambiguous proof artifacts, mismatched consumed digests, accepted replay, mismatched numeric service-account audit identity, failed disable Admin Activity, false-safe receipt/signature mutations, forged console state, or blocking special-file input.

## Validate deterministic artifacts

The compilers consume explicit reviewed JSON and never discover or receive a private key value:

```sh
npm run plan:wif -- wif-input.json wif-plan.json
npm run cutover -- plan .github/workflows/k0-deploy.yml k0/templates/k0-deploy.wif.yml cutover-plan.json
npm run cutover -- apply .github/workflows/k0-deploy.yml k0/templates/k0-deploy.wif.yml cutover-plan.json k0-deploy.generated.yml
node bin/k0-bundle.mjs assemble input.json new-output-dir
node bin/k0-bundle.mjs verify bundle-dir
```

The assembler input is the exact credential-free `{manifest,evidence}` shape. It validates the complete v3 bundle in memory before creating `new-output-dir`, never overwrites an existing file, directory, or symlink, and writes only canonical `manifest.json` plus exact `artifacts/E###.json`. `verify` uses the same bounded, nonblocking, no-follow loader, rejects missing/extra/noncanonical/tampered/credential-shaped files, and performs no network, cloud, or KMS call.

Local receipt code deterministically reconstructs only `K0_VERIFIED_RECEIPT_PENDING` with `RECOLLECTION_REQUIRED` and `release_ready: false`. It can prepare an inert KMS digest request and verify a returned canonical signature sidecar against an out-of-band pinned public key. There is no signing command, KMS client, private-key fallback, or local release promotion; even a valid signature remains pending the separate human release boundary.

The published RC also contains a filesafe authenticated pending-issuance CLI. It exists, is tested, and is merged, but it has not been run against an eligible live transaction. The already-disabled historical transaction cannot be used because its canonical v3 archive checkpoint was not reviewed and merged before disable; never re-enable that key to repair it. An authorized operator must instead supply a strict credential-free plan referencing the exact archive from a separately authorized fresh disposable transaction, a GitHub read token only through `KEYLESS_GITHUB_TOKEN`, and existing read-only GCP ADC. The verifier selects the earliest authoritative occurrence time, checkpoint-receipt `recorded_at`, or checkpoint event time across the final evidence and requires `manifest.assembled_at`—the latest authenticated final collection—to be no more than 48 hours later. Archive or checkpoint sealing and later recollection cannot reset, backdate, or extend that window. From the intended private output directory, the generic shape is:

```sh
cd "$PRIVATE_OUTPUT_DIR"
KEYLESS_GITHUB_TOKEN="$GITHUB_READ_TOKEN" \
  node "$REPO_ROOT/bin/k0-live-issuer.mjs" "$PLAN_FILE" pending-output.json
```

The exact second argument is a safe JSON basename, not a path. The command atomically refuses an existing file, symlink, FIFO, or competing writer before authentication, then writes and rereads one canonical mode-`0600` envelope through the reserved handle. On an ordinary pre-commit failure it attempts, through that held handle, to restore mode `0600`, truncate the file, and if needed write and sync an invalid `0xFF` first byte; when those mutations succeed, the residue is private and verifier-invalid. If every held-handle mutation fails, the command still fails, never marks the output committed, and never unlinks or writes through the path, but it cannot guarantee that the residue is invalid or private. Treat any file from a failed run as untrusted: inspect it manually, choose a new basename for a retry, and never treat it as committed. The envelope contains the verified bundle, pending receipt, and inert KMS request; it never contains a signature or release authorization.

## Live operator commands

These four executables are the only ones that touch live GitHub or Google state, and none of them mutates it. All four are read-only apart from the one Firestore write in `proofv2 issue`. Every one refuses to overwrite an existing file, directory, or symlink and writes mode-`0600` output. They take a GitHub token only through `KEYLESS_GITHUB_TOKEN`, never as an argument, and use existing read-only GCP application-default credentials.

### ProofV2 operator

```sh
npm run proofv2 -- issue --project-id P --migration-id M --owner-id N --repository-id N \
  --workflow-path .github/workflows/k0-proof-v2.yml --client-email SA@P.iam.gserviceaccount.com
npm run proofv2 -- verify --project-id P --owner OWNER --repository REPO --run-id N \
  --workflow-path .github/workflows/k0-proof-v2.yml
```

`issue` performs exactly one Firestore document creation and prints only the five bounded workflow-dispatch inputs; it never dispatches anything. `verify` is read-only in GitHub and Google IAM until the signed proof, exact completed run, workflow blob, and independent environment review all agree, then atomically moves that one challenge from `ISSUED` to `CONSUMED` and proves a second consume is rejected. The challenge expires exactly five minutes after issuance, so do not issue until the dispatcher is ready; an expired challenge cannot be re-dispatched or reissued without a new explicit write permission. Full operator mechanics and the required human approvals are in [REVIEWER_RUNBOOK.md](REVIEWER_RUNBOOK.md).

### Pre-disable collectors

```sh
node bin/k0-predisable-collect.mjs observe-forbidden collect-plan.json forbidden-before.json

KEYLESS_GITHUB_TOKEN="$GITHUB_READ_TOKEN" \
  node bin/k0-predisable-collect.mjs collect \
    collect-plan.json operator-receipt.json forbidden-before.json new-output-dir
```

**Run `observe-forbidden` before the first hostile probe starts.** It records the forbidden Cloud Run service's revision, and the verifier requires that observation to be strictly earlier than H8's start time. The `collect` plan cannot be written until H8 exists, so the two cannot be run together: an observation taken after the probes is late, and a late observation cannot be repaired by re-reading the service. That ordering is the only reason the collector is split into two commands.

`collect` then refetches the exact approvals, runs, jobs, logs, artifacts, Cloud Run revisions, WIF provider/IAM state, and audit entries named by the plan, and writes `bundle-input.json`, `archive-plan.json`, and `checkpoint-receipt.json` into a new mode-`0700` directory. It removes that directory if any step fails, so a partial collection is never left behind as evidence.

### Pre-disable archive

```sh
node bin/k0-predisable-archive.mjs archive-plan.json artifact-dir new-output-dir
```

Takes the `archive-plan.json` from `collect` plus the exact artifact directory it names, seals them into one canonical `predisable-archive.json`, and re-verifies the written bytes before returning. Commit that file through a protected pull request, obtain independent review of its exact head, and merge it **while the fresh key is still enabled** — the verifier requires the checkpoint's `test` check and `main` push run to complete strictly before the key-disable audit timestamp, so a checkpoint merged after disable can never be repaired.

## Evaluate agent necessity

```sh
npm run run:eval -- predictions.json
npm run score:eval -- predictions.json
```

Live evaluation requires valid Vertex AI application-default credentials and the configured Gemini model. Raw model outputs are local evidence and must not be committed. Security verdicts are always deterministic; the model does not judge authorization or receipt completeness.

## Live K0

Do not reproduce K0 by copying credentials from another project. Use a disposable project/repository, a dedicated deployment service account, protected `main`, protected `production`, a human reviewer/key operator, and the exact support matrix. Follow [Development chunks](DEVELOPMENT_PLAN.md) and the [independent reviewer/operator runbook](REVIEWER_RUNBOOK.md).

Stop on key ambiguity, shared or broad authority, source drift, missing review, hostile success, forbidden-target change, secret exposure, or failed post-disable WIF continuity.
