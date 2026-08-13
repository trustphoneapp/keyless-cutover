import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HOSTILE_CASES = {
  H1: ["WRONG_OWNER_ID", "WIF_PROVIDER_CONDITION"],
  H2: ["WRONG_REPOSITORY_ID", "WIF_PROVIDER_CONDITION"],
  H3: ["WRONG_REF", "WIF_PROVIDER_CONDITION"],
  H4: ["WRONG_WORKFLOW_REF", "WIF_PROVIDER_CONDITION"],
  H5: ["WRONG_EVENT", "WIF_PROVIDER_CONDITION"],
  H6: ["WRONG_ENVIRONMENT", "WIF_PROVIDER_CONDITION"],
  H7: ["WRONG_AUDIENCE", "STS_AUDIENCE"],
  H8: ["FORBIDDEN_RESOURCE", "CLOUD_RUN_IAM"],
};
const EVIDENCE_KINDS = new Set([
  "GITHUB_RUN",
  "GITHUB_ENVIRONMENT_REVIEW",
  "PROOFV2_ARTIFACT",
  "GCP_IAM_KEY",
  "GCP_WIF_PROVIDER",
  "GCP_IAM_POLICY",
  "STS_CLIENT_RESULT",
  "CLOUD_RUN_IAM_RESULT",
  "CLOUD_RUN_REVISION",
  "GCP_AUDIT_ENTRY",
  "GOOGLE_AUTH_RESULT",
  "LEAK_SCAN",
]);
const TOP_LEVEL = new Set([
  "version",
  "scope",
  "revisions",
  "evidence",
  "proof",
  "wif",
  "hostile_tests",
  "disable",
  "legacy_after_disable",
  "post_disable",
  "leak_scan",
  "limitations",
]);
const EVIDENCE_FIELDS = new Set(["id", "kind", "locator", "observed_at", "sha256", "public_url"]);
const CREDENTIAL = /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"private_key"\s*:|ya29\.[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35})/;
const SHA256 = /^[a-f0-9]{64}$/;
const SOURCE_ID = /^E[0-9]{3}$/;
const NUMERIC_ID = /^\d+$/;
const KEY_ID = /^[a-f0-9]{40}$/;
const SERVICE_ACCOUNT = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;
const WORKFLOW_PATH = /^\.github\/workflows\/[A-Za-z0-9._/-]+\.ya?ml$/;
const SERVICE = /^[a-z][a-z0-9-]{0,62}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

function present(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 2048 && !/[\r\n]/.test(value);
}

function exact(value, pattern) {
  return typeof value === "string" && pattern.test(value);
}

export function verifyK0Manifest(manifest) {
  const errors = [];
  const fail = (condition, message) => {
    if (!condition) errors.push(message);
  };
  fail(manifest && typeof manifest === "object" && !Array.isArray(manifest), "manifest must be an object");
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) return { ok: false, errors };
  fail(JSON.stringify(manifest).length <= 1_000_000, "manifest is too large");
  fail(Object.keys(manifest).every((key) => TOP_LEVEL.has(key)), "manifest has unknown top-level fields");
  fail(manifest.version === 2, "version must be 2");

  const scope = manifest.scope ?? {};
  fail(exact(scope.owner_id, NUMERIC_ID), "scope.owner_id is invalid");
  fail(exact(scope.repository_id, NUMERIC_ID), "scope.repository_id is invalid");
  fail(exact(scope.workflow_path, WORKFLOW_PATH), "scope.workflow_path is invalid");
  fail(exact(scope.project_number, NUMERIC_ID), "scope.project_number is invalid");
  fail(exact(scope.service_account_email, SERVICE_ACCOUNT), "scope.service_account_email is invalid");
  fail(exact(scope.key_id, KEY_ID), "scope.key_id is invalid");
  fail(exact(scope.allowed_service, SERVICE), "scope.allowed_service is invalid");
  fail(exact(scope.forbidden_service, SERVICE), "scope.forbidden_service is invalid");
  fail(scope.allowed_service !== scope.forbidden_service, "allowed and forbidden services must differ");

  const revisions = manifest.revisions ?? {};
  for (const key of ["legacy_1", "wif_1", "wif_2", "forbidden_before", "forbidden_after"]) {
    fail(exact(revisions[key], SERVICE), `revisions.${key} is invalid`);
  }
  fail(new Set([revisions.legacy_1, revisions.wif_1, revisions.wif_2]).size === 3, "deployment revisions must be distinct");
  fail(revisions.forbidden_before === revisions.forbidden_after, "forbidden service changed");

  const evidenceItems = Array.isArray(manifest.evidence) ? manifest.evidence : [];
  fail(evidenceItems.length > 0 && evidenceItems.length <= 100, "evidence ledger size is invalid");
  const evidence = new Map();
  for (const item of evidenceItems) {
    fail(item && typeof item === "object" && !Array.isArray(item), "evidence entry must be an object");
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    fail(Object.keys(item).every((key) => EVIDENCE_FIELDS.has(key)), `${item.id ?? "unknown"} has unknown evidence fields`);
    fail(exact(item.id, SOURCE_ID), "evidence ID is invalid");
    fail(EVIDENCE_KINDS.has(item.kind), `${item.id ?? "unknown"} evidence kind is invalid`);
    fail(present(item.locator), `${item.id ?? "unknown"} locator is invalid`);
    fail(exact(item.observed_at, TIMESTAMP) && Number.isFinite(Date.parse(item.observed_at)), `${item.id ?? "unknown"} observed_at is invalid`);
    fail(exact(item.sha256, SHA256), `${item.id ?? "unknown"} sha256 is invalid`);
    fail(item.public_url === undefined || /^https:\/\//.test(item.public_url), `${item.id ?? "unknown"} public_url is invalid`);
    fail(!evidence.has(item.id), `${item.id ?? "unknown"} evidence ID is duplicated`);
    if (exact(item.id, SOURCE_ID) && !evidence.has(item.id)) evidence.set(item.id, item);
  }
  const used = new Set();
  const requireSources = (value, requiredKinds, label) => {
    fail(Array.isArray(value) && value.length > 0 && value.every((id) => exact(id, SOURCE_ID)), `${label} source identifiers are invalid`);
    if (!Array.isArray(value)) return;
    const items = value.map((id) => evidence.get(id));
    for (const id of value) {
      used.add(id);
      fail(evidence.has(id), `${label} references missing evidence ${id}`);
    }
    for (const kind of requiredKinds) fail(items.some((item) => item?.kind === kind), `${label} requires ${kind} evidence`);
  };

  const proof = manifest.proof ?? {};
  fail(proof.challenge_status === "CONSUMED", "ProofV2 challenge was not consumed");
  fail(present(proof.challenge_id) && exact(proof.proof_digest, SHA256), "ProofV2 identifiers are invalid");
  fail(proof.key_id === scope.key_id, "ProofV2 key does not match scope");
  requireSources(proof.source_ids, ["GITHUB_RUN", "GITHUB_ENVIRONMENT_REVIEW", "PROOFV2_ARTIFACT", "GCP_IAM_KEY"], "ProofV2");

  const wif = manifest.wif ?? {};
  fail(wif.no_added_downstream_permissions === true, "downstream permission parity is not proven");
  fail(/^projects\/\d+\/locations\/global\/workloadIdentityPools\/[a-z0-9-]+\/providers\/[a-z0-9-]+$/.test(wif.provider ?? ""), "WIF provider is invalid");
  fail(exact(wif.config_hash, SHA256) && exact(wif.iam_diff_hash, SHA256), "WIF hashes are invalid");
  requireSources(wif.source_ids, ["GCP_WIF_PROVIDER", "GCP_IAM_POLICY"], "WIF");

  const tests = Array.isArray(manifest.hostile_tests) ? manifest.hostile_tests : [];
  fail(tests.length === 8, "exactly eight hostile tests are required");
  const byId = new Map(tests.map((test) => [test?.id, test]));
  fail(byId.size === 8, "hostile test IDs must be unique");
  for (const [id, [identityCase, control]] of Object.entries(HOSTILE_CASES)) {
    const hostile = byId.get(id) ?? {};
    fail(hostile.identity_case === identityCase, `${id} identity case is wrong`);
    fail(hostile.expected_control === control, `${id} expected control is wrong`);
    fail(hostile.reached_control === true, `${id} did not reach its intended control`);
    fail(hostile.outcome === "DENIED", `${id} was not denied`);
    fail(exact(hostile.target_revision_before, SERVICE) && hostile.target_revision_before === hostile.target_revision_after, `${id} target changed or revision evidence is invalid`);
    requireSources(
      hostile.source_ids,
      id === "H8" ? ["GITHUB_RUN", "CLOUD_RUN_IAM_RESULT", "CLOUD_RUN_REVISION"] : ["GITHUB_RUN", "STS_CLIENT_RESULT", "CLOUD_RUN_REVISION"],
      id,
    );
  }

  const disable = manifest.disable ?? {};
  fail(disable.key_id === scope.key_id, "disabled key does not match scope");
  fail(disable.observed_disabled === true && present(disable.human_actor), "human key disable is not proven");
  requireSources(disable.source_ids, ["GCP_IAM_KEY", "GCP_AUDIT_ENTRY"], "key disable");

  const legacy = manifest.legacy_after_disable ?? {};
  fail(legacy.fresh_runner === true && legacy.fresh_online_request === true, "legacy denial was not fresh and online");
  fail(legacy.outcome === "DENIED", "fresh legacy authentication did not fail");
  requireSources(legacy.source_ids, ["GITHUB_RUN", "GOOGLE_AUTH_RESULT"], "legacy denial");

  const post = manifest.post_disable ?? {};
  fail(post.fresh_runner === true && post.outcome === "SUCCEEDED", "post-disable WIF did not succeed freshly");
  fail(post.revision === revisions.wif_2, "post-disable revision does not match wif_2");
  requireSources(post.source_ids, ["GITHUB_RUN", "CLOUD_RUN_REVISION"], "post-disable WIF");

  fail(manifest.leak_scan?.outcome === "CLEAN", "credential leak scan is not clean");
  requireSources(manifest.leak_scan?.source_ids, ["LEAK_SCAN"], "leak scan");
  fail(Array.isArray(manifest.limitations) && manifest.limitations.length > 0 && manifest.limitations.every(present), "limitations must be a non-empty array of bounded strings");
  for (const id of evidence.keys()) fail(used.has(id), `${id} is unreferenced evidence`);
  fail(!CREDENTIAL.test(JSON.stringify(manifest)), "manifest contains credential-shaped material");
  return { ok: errors.length === 0, errors };
}

async function main(path) {
  if (!path) throw new Error("Usage: node src/k0-manifest.mjs <manifest.json>");
  const manifest = JSON.parse(await readFile(resolve(path), "utf8"));
  const result = verifyK0Manifest(manifest);
  if (!result.ok) throw new Error(result.errors.join("\n"));
  process.stdout.write("K0 manifest verified\n");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv[2]).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
