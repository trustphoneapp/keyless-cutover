import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const NUMBER = /^\d+$/;
const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const RESOURCE_ID = /^[a-z][a-z0-9-]{3,31}$/;
const REPO_PART = /^[A-Za-z0-9_.-]{1,100}$/;
const SERVICE_ACCOUNT = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;

function exact(value, name, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function buildWifPlan(input) {
  const projectNumber = exact(input.project_number, "project_number", NUMBER);
  const projectId = exact(input.project_id, "project_id", PROJECT_ID);
  const poolId = exact(input.pool_id, "pool_id", RESOURCE_ID);
  const providerId = exact(input.provider_id, "provider_id", RESOURCE_ID);
  const ownerId = exact(input.owner_id, "owner_id", NUMBER);
  const repositoryId = exact(input.repository_id, "repository_id", NUMBER);
  const owner = exact(input.owner, "owner", REPO_PART);
  const repository = exact(input.repository, "repository", REPO_PART);
  const serviceAccount = exact(input.service_account, "service_account", SERVICE_ACCOUNT);
  const provider = `projects/${projectNumber}/locations/global/workloadIdentityPools/${poolId}/providers/${providerId}`;
  const audience = `https://iam.googleapis.com/${provider}`;
  const workflowRef = `${owner}/${repository}/.github/workflows/k0-deploy.yml@refs/heads/main`;
  const attributeMapping = {
    "google.subject": "assertion.sub",
    "attribute.owner_id": "assertion.repository_owner_id",
    "attribute.repo_id": "assertion.repository_id",
    "attribute.ref": "assertion.ref",
    "attribute.workflow_ref": "assertion.workflow_ref",
    "attribute.event": "assertion.event_name",
    "attribute.environment": "assertion.environment",
    "attribute.runner": "assertion.runner_environment",
  };
  const condition = [
    `assertion.repository_owner_id=='${ownerId}'`,
    `assertion.repository_id=='${repositoryId}'`,
    "assertion.ref=='refs/heads/main'",
    `assertion.workflow_ref=='${workflowRef}'`,
    "assertion.event_name=='push'",
    "assertion.environment=='production'",
    "assertion.runner_environment=='github-hosted'",
    `assertion.aud=='${audience}'`,
  ].join(" && ");
  const member = `principalSet://iam.googleapis.com/projects/${projectNumber}/locations/global/workloadIdentityPools/${poolId}/attribute.repo_id/${repositoryId}`;
  const body = {
    version: 1,
    project_id: projectId,
    project_number: projectNumber,
    issuer: "https://token.actions.githubusercontent.com/",
    pool_id: poolId,
    provider_id: providerId,
    provider,
    audience,
    service_account: serviceAccount,
    workflow_ref: workflowRef,
    attribute_mapping: attributeMapping,
    attribute_condition: condition,
    impersonation_binding: {
      resource: serviceAccount,
      role: "roles/iam.workloadIdentityUser",
      member,
    },
    commands: [
      ["gcloud", "iam", "workload-identity-pools", "create", poolId, `--project=${projectId}`, "--location=global", "--display-name=Keyless K0"],
      [
        "gcloud", "iam", "workload-identity-pools", "providers", "create-oidc", providerId,
        `--project=${projectId}`, "--location=global", `--workload-identity-pool=${poolId}`,
        "--issuer-uri=https://token.actions.githubusercontent.com/",
        `--attribute-mapping=${Object.entries(attributeMapping).map(([key, value]) => `${key}=${value}`).join(",")}`,
        `--attribute-condition=${condition}`,
      ],
      [
        "gcloud", "iam", "service-accounts", "add-iam-policy-binding", serviceAccount,
        `--project=${projectId}`, "--role=roles/iam.workloadIdentityUser", `--member=${member}`,
      ],
    ],
  };
  return { ...body, plan_digest: digest(JSON.stringify(body)) };
}

export function verifyWifPlan(input, approvedPlan) {
  const actual = buildWifPlan(input);
  return JSON.stringify(actual) === JSON.stringify(approvedPlan);
}

async function main([inputPath, outputPath]) {
  if (!inputPath || !outputPath) throw new Error("Usage: node src/wif-plan.mjs <input.json> <plan.json>");
  const plan = buildWifPlan(JSON.parse(await readFile(resolve(inputPath), "utf8")));
  await writeFile(resolve(outputPath), `${JSON.stringify(plan, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  process.stdout.write(`${plan.plan_digest}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
