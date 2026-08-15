import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { applyCutoverPlan, buildCutoverPlan } from "../src/workflow-cutover.mjs";

const current = await readFile(new URL("../k0/fixtures/k0-deploy.legacy.yml", import.meta.url), "utf8");
const template = await readFile(new URL("../k0/templates/k0-deploy.wif.yml", import.meta.url), "utf8");

test("cutover compiler emits only the exact approved same-path WIF bytes", () => {
  const plan = buildCutoverPlan(current, template);

  assert.equal(applyCutoverPlan(current, template, plan), template);
  assert.equal(plan.preserves_workflow_path, true);
  assert.equal(plan.removes_credentials_json, true);
  for (const id of ["h3", "h5", "h6", "h7", "h8"]) assert.match(template, new RegExp(`${id}-`));
  assert.throws(() => applyCutoverPlan(`${current}\n# drift\n`, template, plan), /does not match/);
  assert.throws(() => buildCutoverPlan(current, template.replace("@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093", "@v3")), /unpinned/);
  assert.throws(() => buildCutoverPlan(current, `${template}\n# credentials_json:\n`), /exact WIF/);
  assert.throws(() => buildCutoverPlan(current, template, ".github/workflows/other.yml"), /unsupported/);
});

test("cutover compiler refuses credential retention, privilege widening, and hostile-job drift", () => {
  assert.throws(() => buildCutoverPlan(current, template.replace("id-token: write", "contents: write")), /exact WIF/);
  assert.throws(() => buildCutoverPlan(current, template.replace("branches: [main, keyless-h3]", "branches: [main]")), /missing/);
  assert.throws(() => buildCutoverPlan(current, template.replace("h8-forbidden-resource:", "h8-disabled:")), /missing/);
  assert.throws(() => buildCutoverPlan(current, `${template}\npull_request_target:\n`), /forbidden/);
  assert.throws(() => buildCutoverPlan(current, `${template}\n    runs-on: self-hosted\n`), /forbidden/);
  assert.throws(() => buildCutoverPlan(current.replace("credentials_json:", "token:"), template), /legacy authentication/);
  assert.throws(() => buildCutoverPlan(`${current}\npermissions:\n  id-token: write\n`, template), /legacy authentication/);
  assert.throws(() => buildCutoverPlan(`${current}\0`, template), /NUL/);
  assert.throws(() => buildCutoverPlan(current, `${template}\0`), /NUL/);
  assert.throws(
    () => buildCutoverPlan(`${current}\n# -----BEGIN DSA PRIVATE KEY-----\n`, template),
    /credential-shaped/,
  );
  assert.throws(
    () => buildCutoverPlan(current, `${template}\nbearer ${"a".repeat(24)}\n`),
    /credential-shaped/,
  );

  const plan = buildCutoverPlan(current, template);
  assert.throws(() => applyCutoverPlan(current, template.replace("name: K0 deploy", "name: K0 other"), plan), /does not match|workflow name/);
  assert.throws(
    () => applyCutoverPlan(current, template, { ...plan, plan_digest: "0".repeat(64) }),
    /does not match/,
  );
});

test("reviewed WIF template still compiles from the frozen legacy fixture", async () => {
  const fixture = await readFile(new URL("../k0/fixtures/k0-deploy.legacy.yml", import.meta.url), "utf8");
  const reviewed = await readFile(new URL("../k0/templates/k0-deploy.wif.yml", import.meta.url), "utf8");
  const plan = buildCutoverPlan(fixture, reviewed);
  assert.equal(applyCutoverPlan(fixture, reviewed, plan), reviewed);
  assert.equal(plan.removes_credentials_json, true);
  assert.doesNotMatch(reviewed, /credentials_json:/);
  assert.match(reviewed, /id-token: write/);
  assert.match(reviewed, /workload_identity_provider:/);
});

test("cutover apply CLI refuses duplicate JSON plan keys", async () => {
  const { mkdtemp, writeFile, rm } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const { spawnSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const directory = await mkdtemp(join(tmpdir(), "keyless-cutover-cli-"));
  try {
    const currentPath = join(directory, "current.yml");
    const templatePath = join(directory, "template.yml");
    const planPath = join(directory, "plan.json");
    const outputPath = join(directory, "out.yml");
    await writeFile(currentPath, current);
    await writeFile(templatePath, template);
    await writeFile(planPath, '{"version":1,"version":2}\n');
    const cli = fileURLToPath(new URL("../src/workflow-cutover.mjs", import.meta.url));
    const result = spawnSync(process.execPath, [cli, "apply", currentPath, templatePath, planPath, outputPath], {
      encoding: "utf8",
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /duplicate JSON key/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
