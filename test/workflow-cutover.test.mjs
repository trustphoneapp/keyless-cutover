import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { applyCutoverPlan, buildCutoverPlan } from "../src/workflow-cutover.mjs";

const current = await readFile(new URL("../.github/workflows/k0-deploy.yml", import.meta.url), "utf8");
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
