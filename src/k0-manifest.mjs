import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HOSTILE_CONTROLS = {
  H1: "WIF_PROVIDER_CONDITION",
  H2: "WIF_PROVIDER_CONDITION",
  H3: "WIF_PROVIDER_CONDITION",
  H4: "WIF_PROVIDER_CONDITION",
  H5: "WIF_PROVIDER_CONDITION",
  H6: "WIF_PROVIDER_CONDITION",
  H7: "STS_AUDIENCE",
  H8: "CLOUD_RUN_IAM",
};
const TOP_LEVEL = new Set([
  "version",
  "scope",
  "revisions",
  "proof",
  "wif",
  "hostile_tests",
  "disable",
  "legacy_after_disable",
  "post_disable",
  "leak_scan",
  "limitations",
]);
const CREDENTIAL = /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"private_key"\s*:|ya29\.[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35})/;

function present(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 1024;
}

function sources(value) {
  return Array.isArray(value) && value.length > 0 && value.every(present);
}

export function verifyK0Manifest(manifest) {
  const errors = [];
  const fail = (condition, message) => {
    if (!condition) errors.push(message);
  };
  fail(manifest && typeof manifest === "object" && !Array.isArray(manifest), "manifest must be an object");
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) return { ok: false, errors };
  fail(Object.keys(manifest).every((key) => TOP_LEVEL.has(key)), "manifest has unknown top-level fields");
  fail(manifest.version === 1, "version must be 1");

  const scope = manifest.scope ?? {};
  for (const key of [
    "owner_id",
    "repository_id",
    "workflow_path",
    "project_number",
    "service_account_email",
    "key_id",
    "allowed_service",
    "forbidden_service",
  ]) fail(present(scope[key]), `scope.${key} is required`);
  fail(scope.allowed_service !== scope.forbidden_service, "allowed and forbidden services must differ");

  const revisions = manifest.revisions ?? {};
  for (const key of ["legacy_1", "wif_1", "wif_2", "forbidden_before", "forbidden_after"]) {
    fail(present(revisions[key]), `revisions.${key} is required`);
  }
  fail(new Set([revisions.legacy_1, revisions.wif_1, revisions.wif_2]).size === 3, "deployment revisions must be distinct");
  fail(revisions.forbidden_before === revisions.forbidden_after, "forbidden service changed");

  const proof = manifest.proof ?? {};
  fail(proof.challenge_status === "CONSUMED", "ProofV2 challenge was not consumed");
  fail(present(proof.challenge_id) && present(proof.proof_digest), "ProofV2 identifiers are required");
  fail(proof.key_id === scope.key_id, "ProofV2 key does not match scope");
  fail(sources(proof.source_ids), "ProofV2 source identifiers are required");

  const wif = manifest.wif ?? {};
  fail(wif.no_added_downstream_permissions === true, "downstream permission parity is not proven");
  fail(present(wif.provider) && present(wif.config_hash) && present(wif.iam_diff_hash), "WIF evidence is incomplete");
  fail(sources(wif.source_ids), "WIF source identifiers are required");

  const tests = Array.isArray(manifest.hostile_tests) ? manifest.hostile_tests : [];
  fail(tests.length === 8, "exactly eight hostile tests are required");
  const byId = new Map(tests.map((test) => [test?.id, test]));
  fail(byId.size === 8, "hostile test IDs must be unique");
  for (const [id, control] of Object.entries(HOSTILE_CONTROLS)) {
    const test = byId.get(id) ?? {};
    fail(test.expected_control === control, `${id} expected control is wrong`);
    fail(test.reached_control === true, `${id} did not reach its intended control`);
    fail(test.outcome === "DENIED", `${id} was not denied`);
    fail(sources(test.source_ids), `${id} source identifiers are required`);
  }

  const disable = manifest.disable ?? {};
  fail(disable.key_id === scope.key_id, "disabled key does not match scope");
  fail(disable.observed_disabled === true && present(disable.human_actor), "human key disable is not proven");
  fail(sources(disable.source_ids), "key-disable source identifiers are required");

  const legacy = manifest.legacy_after_disable ?? {};
  fail(legacy.fresh_runner === true && legacy.fresh_online_request === true, "legacy denial was not fresh and online");
  fail(legacy.outcome === "DENIED", "fresh legacy authentication did not fail");
  fail(sources(legacy.source_ids), "legacy-denial source identifiers are required");

  const post = manifest.post_disable ?? {};
  fail(post.fresh_runner === true && post.outcome === "SUCCEEDED", "post-disable WIF did not succeed freshly");
  fail(post.revision === revisions.wif_2, "post-disable revision does not match wif_2");
  fail(sources(post.source_ids), "post-disable source identifiers are required");

  fail(manifest.leak_scan?.outcome === "CLEAN" && sources(manifest.leak_scan?.source_ids), "credential leak scan is not clean");
  fail(Array.isArray(manifest.limitations) && manifest.limitations.every(present), "limitations must be an array of bounded strings");
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
