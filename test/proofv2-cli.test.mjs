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
