import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const cli = fileURLToPath(new URL("../bin/proofv2-operator.mjs", import.meta.url));

test("ProofV2 CLI never accepts or echoes a command-line credential", () => {
  const credential = `gho_${"s".repeat(36)}`;
  const result = spawnSync(process.execPath, [cli, "verify", "--token", credential], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unsupported option --token/);
  assert.equal(`${result.stdout}${result.stderr}`.includes(credential), false);
});

test("ProofV2 CLI validates project identity before constructing Firestore", () => {
  const result = spawnSync(process.execPath, [
    cli,
    "issue",
    "--project-id", "../wrong",
    "--migration-id", "migration",
    "--owner-id", "1",
    "--repository-id", "2",
    "--workflow-path", ".github/workflows/k0-proof-v2.yml",
    "--client-email", "deploy@example.iam.gserviceaccount.com",
  ], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /project-id is invalid/);
});

test("ProofV2 CLI validates issue and verify arguments before Firestore", () => {
  const baseIssue = [
    cli, "issue",
    "--project-id", "keyless-k0-demo",
    "--migration-id", "migration",
    "--owner-id", "1",
    "--repository-id", "2",
    "--workflow-path", ".github/workflows/k0-proof-v2.yml",
    "--client-email", "deploy@example.iam.gserviceaccount.com",
  ];
  for (const [argv, pattern] of [
    [["--owner-id", "abc"], /owner-id is invalid/],
    [["--repository-id", " "], /repository-id is invalid/],
    [["--workflow-path", "workflows/k0-proof-v2.yml"], /workflow-path is invalid/],
    [["--client-email", "deploy@example.com"], /client-email is invalid/],
    [["--migration-id", " \t"], /migration-id is invalid/],
  ]) {
    const args = [...baseIssue];
    for (let index = 0; index < args.length - 1; index += 1) {
      if (args[index] === argv[0]) args[index + 1] = argv[1];
    }
    const result = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, pattern);
  }

  const verify = spawnSync(process.execPath, [
    cli, "verify",
    "--project-id", "keyless-k0-demo",
    "--owner", "../evil",
    "--repository", "keyless-cutover",
    "--run-id", "123",
    "--workflow-path", ".github/workflows/k0-proof-v2.yml",
  ], { encoding: "utf8", env: { ...process.env, KEYLESS_GITHUB_TOKEN: `ghs_${"t".repeat(36)}` } });
  assert.notEqual(verify.status, 0);
  assert.match(verify.stderr, /owner is invalid/);
});
