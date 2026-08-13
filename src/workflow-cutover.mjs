import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const WORKFLOW_PATH = ".github/workflows/k0-deploy.yml";
const MAX_WORKFLOW_BYTES = 64 * 1024;
const WIF_AUTH_STEP_COUNT = 6;

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function count(value, needle) {
  return value.split(needle).length - 1;
}

function countIndentedKey(value, key) {
  return [...value.matchAll(new RegExp(`^\\s+${key}:`, "gm"))].length;
}

function workflowName(value) {
  return value.match(/^name:\s*(.+)$/m)?.[1]?.trim();
}

function validatePinnedActions(value, label) {
  const uses = [...value.matchAll(/^\s*-?\s*uses:\s*([^\s#]+).*$/gm)].map((match) => match[1]);
  if (!uses.length || uses.some((entry) => !/@[a-f0-9]{40}$/.test(entry))) {
    throw new Error(`${label} contains an unpinned action`);
  }
}

function validateWorkflows(current, template) {
  if (!Buffer.byteLength(current) || Buffer.byteLength(current) > MAX_WORKFLOW_BYTES) {
    throw new Error("current workflow size is invalid");
  }
  if (!Buffer.byteLength(template) || Buffer.byteLength(template) > MAX_WORKFLOW_BYTES) {
    throw new Error("template workflow size is invalid");
  }
  validatePinnedActions(current, "current workflow");
  validatePinnedActions(template, "WIF template");
  if (!workflowName(current) || workflowName(current) !== workflowName(template)) {
    throw new Error("workflow name changed");
  }
  if (count(current, "credentials_json:") !== 1 || current.includes("id-token: write")) {
    throw new Error("current workflow is not the exact legacy authentication shape");
  }
  if (
    template.includes("credentials_json:") ||
    countIndentedKey(template, "workload_identity_provider") !== WIF_AUTH_STEP_COUNT ||
    countIndentedKey(template, "service_account") !== WIF_AUTH_STEP_COUNT ||
    countIndentedKey(template, "audience") !== WIF_AUTH_STEP_COUNT ||
    count(template, "id-token: write") !== 1
  ) {
    throw new Error("template is not the exact WIF authentication shape");
  }
  for (const required of [
    "branches: [main, keyless-h3]",
    "workflow_dispatch:",
    "environment: production",
    "vars.GCP_ALLOWED_SERVICE",
    "vars.GCP_CANARY_IMAGE",
    "h3-wrong-ref:",
    "h5-wrong-event:",
    "h6-wrong-environment:",
    "h7-wrong-audience:",
    "h8-forbidden-resource:",
    "vars.GCP_FORBIDDEN_SERVICE",
  ]) {
    if (!template.includes(required)) throw new Error(`template is missing ${required}`);
  }
  for (const forbidden of ["pull_request_target:", "self-hosted", "permissions: write-all"]) {
    if (template.includes(forbidden)) throw new Error(`template contains forbidden value ${forbidden}`);
  }
}

export function buildCutoverPlan(current, template, workflowPath = WORKFLOW_PATH) {
  if (workflowPath !== WORKFLOW_PATH) throw new Error("unsupported workflow path");
  validateWorkflows(current, template);
  const body = {
    version: 1,
    workflow_path: workflowPath,
    current_sha256: digest(current),
    replacement_sha256: digest(template),
    preserves_workflow_path: true,
    removes_credentials_json: true,
    adds_id_token_permission: true,
    human_iam_required: true,
  };
  return { ...body, plan_digest: digest(JSON.stringify(body)) };
}

export function applyCutoverPlan(current, template, approvedPlan) {
  const actual = buildCutoverPlan(current, template, approvedPlan?.workflow_path);
  if (JSON.stringify(actual) !== JSON.stringify(approvedPlan)) {
    throw new Error("approved cutover plan does not match current bytes");
  }
  return template;
}

async function main([command, ...args]) {
  if (command === "plan" && args.length === 3) {
    const [currentPath, templatePath, planPath] = args;
    const plan = buildCutoverPlan(
      await readFile(resolve(currentPath), "utf8"),
      await readFile(resolve(templatePath), "utf8"),
      currentPath,
    );
    await writeFile(resolve(planPath), `${JSON.stringify(plan, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    process.stdout.write(`${plan.plan_digest}\n`);
    return;
  }
  if (command === "apply" && args.length === 4) {
    const [currentPath, templatePath, planPath, outputPath] = args;
    const output = applyCutoverPlan(
      await readFile(resolve(currentPath), "utf8"),
      await readFile(resolve(templatePath), "utf8"),
      JSON.parse(await readFile(resolve(planPath), "utf8")),
    );
    await writeFile(resolve(outputPath), output, { flag: "wx", mode: 0o600 });
    return;
  }
  throw new Error(
    "Usage: node src/workflow-cutover.mjs plan <current> <template> <plan.json> | apply <current> <template> <approved-plan.json> <output>",
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
