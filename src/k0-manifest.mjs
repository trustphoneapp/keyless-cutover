import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { isRfc3339 } from "./rfc3339.mjs";

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
  "GITHUB_PULL_REQUEST",
  "PROOFV2_ARTIFACT",
  "PROOFV2_CHALLENGE_STATE",
  "GCP_IAM_KEY",
  "GCP_WIF_PROVIDER",
  "GCP_IAM_POLICY",
  "GCP_WIF_PARITY",
  "STS_CLIENT_RESULT",
  "CLOUD_RUN_IAM_RESULT",
  "CLOUD_RUN_REVISION",
  "GCP_AUDIT_ENTRY",
  "GOOGLE_AUTH_RESULT",
  "GCP_WIF_AUDIT_LOG",
  "GITHUB_EVIDENCE_CHECKPOINT",
  "LEAK_SCAN",
]);
const TOP_LEVEL = new Set([
  "version",
  "assembled_at",
  "scope",
  "approved_workflows",
  "checkpoint",
  "revisions",
  "evidence",
  "proof",
  "cutover",
  "wif",
  "hostile_tests",
  "legacy_baseline",
  "disable",
  "legacy_after_disable",
  "post_disable",
  "leak_scan",
  "limitations",
]);
const PRE_DISABLE_TOP_LEVEL = new Set([
  "scope", "revisions", "approved_workflows", "legacy_baseline", "proof", "cutover", "wif", "hostile_tests",
]);
const SCOPE_FIELDS = new Set([
  "owner_id", "repository_id", "workflow_path", "proof_workflow_path", "legacy_workflow_path", "h1_workflow_path", "h2_workflow_path", "h4_workflow_path",
  "project_id", "project_number", "region",
  "service_account_email", "service_account_unique_id", "key_id", "allowed_service", "forbidden_service",
]);
const REVISION_FIELDS = new Set([
  "legacy_1", "wif_1", "wif_2", "forbidden_before", "forbidden_after",
  "forbidden_before_source_id", "forbidden_after_hostile_source_id", "forbidden_after_source_id",
]);
const PROOF_FIELDS = new Set(["challenge_status", "challenge_id", "proof_digest", "key_id", "receipt_sha256", "source_ids"]);
const CUTOVER_FIELDS = new Set([
  "pr_number", "reviewed_head_sha", "merge_sha", "wif_1_run_id", "wif_1_run_attempt", "wif_1_head_sha",
  "workflow_blob_sha", "workflow_sha256", "wif_1_release_marker", "source_ids",
]);
const APPROVAL_ROLES = new Set(["baseline", "h1", "h2", "h4", "legacy"]);
const APPROVAL_FIELDS = new Set(["workflow_path", "workflow_blob_sha", "workflow_sha256", "source_id"]);
const CHECKPOINT_FIELDS = new Set(["source_id"]);
const WIF_FIELDS = new Set([
  "mode", "provider", "config_hash", "parity_hash", "idp_subject", "mapped_principal",
  "no_added_downstream_permissions", "source_ids",
]);
const HOSTILE_FIELDS = new Set([
  "id", "identity_case", "expected_control", "reached_control", "outcome",
  "target_revision_before", "target_revision_after", "source_ids",
]);
const LEGACY_BASELINE_FIELDS = new Set([
  "run_id", "run_attempt", "head_sha", "fresh_runner", "outcome", "revision", "release_marker", "source_ids",
]);
const DISABLE_FIELDS = new Set([
  "key_id", "observed_disabled", "human_actor", "service_account_unique_id",
  "audit_insert_id", "audit_timestamp", "source_ids",
]);
const LEGACY_FIELDS = new Set([
  "run_id", "run_attempt", "head_sha", "fresh_runner", "fresh_online_request", "outcome", "source_ids",
]);
const POST_FIELDS = new Set(["run_id", "run_attempt", "head_sha", "fresh_runner", "outcome", "revision", "release_marker", "source_ids"]);
const LEAK_FIELDS = new Set(["outcome", "source_ids"]);
const EVIDENCE_FIELDS = new Set(["id", "kind", "locator", "observed_at", "sha256", "public_url"]);
const CREDENTIAL = /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"private_key"\s*:|ya29\.[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35})/;
const SHA256 = /^[a-f0-9]{64}$/;
const SOURCE_ID = /^E[0-9]{3}$/;
const NUMERIC_ID = /^\d+$/;
const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const KEY_ID = /^[a-f0-9]{40}$/;
const COMMIT_SHA = /^[a-f0-9]{40}$/;
const SERVICE_ACCOUNT = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;
const EMAIL = /^[^@\s]+@[^@\s]+$/;
const WORKFLOW_PATH = /^\.github\/workflows\/[A-Za-z0-9._/-]+\.ya?ml$/;
const REGION = /^[a-z]+-[a-z]+\d$/;
const SERVICE = /^[a-z][a-z0-9-]{0,62}$/;
const LEGACY_BASELINE_BLOB_SHA = "62ec226833a2ac44913044ab665a01b0f0f271db";
const LEGACY_BASELINE_SHA256 = "efa494890963b2744b031a54f78f13df5575b948eec9fa2ec452342fda6feebf";

function present(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 2048 && !/[\r\n]/.test(value);
}

function exact(value, pattern) {
  return typeof value === "string" && pattern.test(value);
}

function validatePreDisableFragment(fragment, evidenceItems, errors) {
  const fail = (condition, message) => {
    if (!condition) errors.push(message);
  };
  fail(fragment && typeof fragment === "object" && !Array.isArray(fragment), "pre-disable fragment must be an object");
  if (!fragment || typeof fragment !== "object" || Array.isArray(fragment)) {
    return { evidence: new Map(), used: new Set(), requireSources: () => {} };
  }
  fail(Object.keys(fragment).length === PRE_DISABLE_TOP_LEVEL.size
    && Object.keys(fragment).every((key) => PRE_DISABLE_TOP_LEVEL.has(key)), "pre-disable fragment fields are invalid");

  const scope = fragment.scope ?? {};
  fail(Object.keys(scope).every((key) => SCOPE_FIELDS.has(key)), "scope has unknown fields");
  fail(exact(scope.owner_id, NUMERIC_ID), "scope.owner_id is invalid");
  fail(exact(scope.repository_id, NUMERIC_ID), "scope.repository_id is invalid");
  fail(scope.workflow_path === ".github/workflows/k0-deploy.yml", "scope.workflow_path is invalid");
  fail(exact(scope.proof_workflow_path, WORKFLOW_PATH) && scope.proof_workflow_path !== scope.workflow_path, "scope.proof_workflow_path is invalid");
  fail(exact(scope.legacy_workflow_path, WORKFLOW_PATH) && scope.legacy_workflow_path !== scope.workflow_path, "scope.legacy_workflow_path is invalid");
  fail(scope.h1_workflow_path === ".github/workflows/k0-deploy.yml", "scope.h1_workflow_path is invalid");
  fail(scope.h2_workflow_path === ".github/workflows/k0-external-hostile.yml", "scope.h2_workflow_path is invalid");
  fail(exact(scope.h4_workflow_path, WORKFLOW_PATH) && scope.h4_workflow_path !== scope.workflow_path,
    "scope.h4_workflow_path is invalid");
  fail(exact(scope.project_id, PROJECT_ID), "scope.project_id is invalid");
  fail(exact(scope.project_number, NUMERIC_ID), "scope.project_number is invalid");
  fail(exact(scope.region, REGION), "scope.region is invalid");
  fail(exact(scope.service_account_email, SERVICE_ACCOUNT), "scope.service_account_email is invalid");
  fail(exact(scope.service_account_unique_id, NUMERIC_ID), "scope.service_account_unique_id is invalid");
  fail(exact(scope.key_id, KEY_ID), "scope.key_id is invalid");
  fail(exact(scope.allowed_service, SERVICE), "scope.allowed_service is invalid");
  fail(exact(scope.forbidden_service, SERVICE), "scope.forbidden_service is invalid");
  fail(scope.allowed_service !== scope.forbidden_service, "allowed and forbidden services must differ");

  const revisions = fragment.revisions ?? {};
  fail(Object.keys(revisions).every((key) => REVISION_FIELDS.has(key)), "revisions has unknown fields");
  for (const key of ["legacy_1", "wif_1", "wif_2", "forbidden_before", "forbidden_after"]) {
    fail(exact(revisions[key], SERVICE), `revisions.${key} is invalid`);
  }
  fail(new Set([revisions.legacy_1, revisions.wif_1, revisions.wif_2]).size === 3, "deployment revisions must be distinct");
  fail(revisions.forbidden_before === revisions.forbidden_after, "forbidden service changed");
  fail(exact(revisions.forbidden_before_source_id, SOURCE_ID), "forbidden-before evidence ID is invalid");
  fail(exact(revisions.forbidden_after_hostile_source_id, SOURCE_ID), "forbidden-after-hostile evidence ID is invalid");
  fail(exact(revisions.forbidden_after_source_id, SOURCE_ID), "forbidden-after evidence ID is invalid");
  fail(new Set([revisions.forbidden_before_source_id, revisions.forbidden_after_hostile_source_id,
    revisions.forbidden_after_source_id]).size === 3, "forbidden observations must be distinct");

  const ledger = Array.isArray(evidenceItems) ? evidenceItems : [];
  fail(ledger.length > 0 && ledger.length <= 100, "evidence ledger size is invalid");
  const evidence = new Map();
  for (const item of ledger) {
    fail(item && typeof item === "object" && !Array.isArray(item), "evidence entry must be an object");
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    fail(Object.keys(item).every((key) => EVIDENCE_FIELDS.has(key)), `${item.id ?? "unknown"} has unknown evidence fields`);
    fail(exact(item.id, SOURCE_ID), "evidence ID is invalid");
    fail(EVIDENCE_KINDS.has(item.kind), `${item.id ?? "unknown"} evidence kind is invalid`);
    fail(present(item.locator), `${item.id ?? "unknown"} locator is invalid`);
    fail(isRfc3339(item.observed_at), `${item.id ?? "unknown"} observed_at is invalid`);
    fail(exact(item.sha256, SHA256), `${item.id ?? "unknown"} sha256 is invalid`);
    fail(item.public_url === undefined || /^https:\/\//.test(item.public_url), `${item.id ?? "unknown"} public_url is invalid`);
    fail(!evidence.has(item.id), `${item.id ?? "unknown"} evidence ID is duplicated`);
    if (exact(item.id, SOURCE_ID) && !evidence.has(item.id)) evidence.set(item.id, item);
  }
  const used = new Set();
  const requireSources = (value, requiredKinds, label) => {
    fail(Array.isArray(value) && value.length > 0 && value.every((id) => exact(id, SOURCE_ID)), `${label} source identifiers are invalid`);
    if (!Array.isArray(value)) return;
    fail(new Set(value).size === value.length, `${label} source identifiers are duplicated`);
    const items = value.map((id) => evidence.get(id));
    for (const id of value) {
      used.add(id);
      fail(evidence.has(id), `${label} references missing evidence ${id}`);
    }
    for (const kind of requiredKinds) fail(items.some((item) => item?.kind === kind), `${label} requires ${kind} evidence`);
  };

  const approvals = fragment.approved_workflows ?? {};
  fail(Object.keys(approvals).length === APPROVAL_ROLES.size
    && Object.keys(approvals).every((role) => APPROVAL_ROLES.has(role)), "approved workflow roles are invalid");
  const approvalPaths = {
    baseline: scope.workflow_path,
    h1: scope.h1_workflow_path,
    h2: scope.h2_workflow_path,
    h4: scope.h4_workflow_path,
    legacy: scope.legacy_workflow_path,
  };
  for (const role of APPROVAL_ROLES) {
    const approval = approvals[role] ?? {};
    fail(Object.keys(approval).length === APPROVAL_FIELDS.size
      && Object.keys(approval).every((key) => APPROVAL_FIELDS.has(key)), `${role} workflow approval fields are invalid`);
    fail(approval.workflow_path === approvalPaths[role], `${role} approved workflow path is invalid`);
    fail(exact(approval.workflow_blob_sha, COMMIT_SHA) && exact(approval.workflow_sha256, SHA256),
      `${role} approved workflow bytes are invalid`);
    requireSources([approval.source_id], ["GITHUB_PULL_REQUEST"], `${role} workflow approval`);
  }
  fail(approvals.baseline?.workflow_blob_sha === LEGACY_BASELINE_BLOB_SHA
    && approvals.baseline?.workflow_sha256 === LEGACY_BASELINE_SHA256,
  "legacy baseline approved workflow bytes do not match the inactive fixture");
  fail(new Set([...APPROVAL_ROLES].map((role) => approvals[role]?.source_id)).size === APPROVAL_ROLES.size,
    "approved workflow evidence must be distinct");
  requireSources([revisions.forbidden_before_source_id], ["CLOUD_RUN_REVISION"], "forbidden-before revision");
  requireSources([revisions.forbidden_after_hostile_source_id], ["CLOUD_RUN_REVISION"], "forbidden-after-hostile revision");

  const proof = fragment.proof ?? {};
  fail(Object.keys(proof).every((key) => PROOF_FIELDS.has(key)), "ProofV2 has unknown fields");
  fail(proof.challenge_status === "CONSUMED", "ProofV2 challenge was not consumed");
  fail(present(proof.challenge_id) && exact(proof.proof_digest, SHA256), "ProofV2 identifiers are invalid");
  fail(exact(proof.receipt_sha256, SHA256), "ProofV2 operator receipt digest is invalid");
  fail(proof.key_id === scope.key_id, "ProofV2 key does not match scope");
  requireSources(proof.source_ids,
    ["GITHUB_RUN", "GITHUB_ENVIRONMENT_REVIEW", "PROOFV2_ARTIFACT", "PROOFV2_CHALLENGE_STATE", "GCP_IAM_KEY"], "ProofV2");
  fail(proof.source_ids?.length === 5, "ProofV2 requires exactly five sources");

  const cutover = fragment.cutover ?? {};
  fail(Object.keys(cutover).every((key) => CUTOVER_FIELDS.has(key)), "cutover has unknown fields");
  fail(Number.isInteger(cutover.pr_number) && cutover.pr_number > 0, "cutover PR number is invalid");
  fail(exact(cutover.reviewed_head_sha, COMMIT_SHA) && exact(cutover.merge_sha, COMMIT_SHA)
    && exact(cutover.wif_1_head_sha, COMMIT_SHA), "cutover commit identity is invalid");
  fail(exact(cutover.workflow_blob_sha, COMMIT_SHA) && exact(cutover.workflow_sha256, SHA256), "cutover workflow identity is invalid");
  fail(exact(cutover.wif_1_release_marker, /^[a-z0-9][a-z0-9-]{0,19}$/), "wif-1 release marker is invalid");
  fail(exact(cutover.wif_1_run_id, NUMERIC_ID) && exact(cutover.wif_1_run_attempt, NUMERIC_ID), "wif-1 run identity is invalid");
  requireSources(cutover.source_ids, ["GITHUB_PULL_REQUEST", "GITHUB_RUN", "GITHUB_ENVIRONMENT_REVIEW", "CLOUD_RUN_REVISION"], "cutover");
  fail(cutover.source_ids?.length === 4, "cutover requires exactly four sources");

  const wif = fragment.wif ?? {};
  fail(Object.keys(wif).every((key) => WIF_FIELDS.has(key)), "WIF has unknown fields");
  fail(wif.mode === "PREEXISTING_EXACT", "WIF parity mode is invalid");
  fail(wif.no_added_downstream_permissions === true, "downstream permission parity is not proven");
  fail(/^projects\/\d+\/locations\/global\/workloadIdentityPools\/[a-z0-9-]+\/providers\/[a-z0-9-]+$/.test(wif.provider ?? ""), "WIF provider is invalid");
  fail(wif.provider?.startsWith(`projects/${scope.project_number}/`), "WIF provider project does not match scope");
  fail(exact(wif.config_hash, SHA256) && exact(wif.parity_hash, SHA256), "WIF hashes are invalid");
  const principalPrefix = `principal://iam.googleapis.com/${wif.provider?.replace(/\/providers\/[a-z0-9-]+$/, "")}/subject/`;
  fail(present(wif.idp_subject), "WIF IdP subject is invalid");
  fail(present(wif.mapped_principal) && wif.mapped_principal.startsWith(principalPrefix)
    && wif.mapped_principal.length > principalPrefix.length, "WIF mapped principal is invalid");
  requireSources(wif.source_ids, ["GCP_WIF_PARITY"], "WIF");
  fail(wif.source_ids?.length === 1, "WIF requires exactly one parity source");

  const tests = Array.isArray(fragment.hostile_tests) ? fragment.hostile_tests : [];
  fail(tests.length === 8, "exactly eight hostile tests are required");
  const byId = new Map(tests.map((test) => [test?.id, test]));
  fail(byId.size === 8, "hostile test IDs must be unique");
  for (const [id, [identityCase, control]] of Object.entries(HOSTILE_CASES)) {
    const hostile = byId.get(id) ?? {};
    fail(Object.keys(hostile).every((key) => HOSTILE_FIELDS.has(key)), `${id} has unknown fields`);
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
    fail(hostile.source_ids?.length === (id === "H8" ? 4 : 3), `${id} source count is invalid`);
    if (id === "H8") {
      fail(hostile.source_ids?.includes(revisions.forbidden_before_source_id)
        && hostile.source_ids?.includes(revisions.forbidden_after_hostile_source_id), "H8 must reference both forbidden revision observations");
    }
  }

  const baseline = fragment.legacy_baseline ?? {};
  fail(Object.keys(baseline).length === LEGACY_BASELINE_FIELDS.size
    && Object.keys(baseline).every((key) => LEGACY_BASELINE_FIELDS.has(key)), "legacy baseline fields are invalid");
  fail(exact(baseline.run_id, NUMERIC_ID) && exact(baseline.run_attempt, NUMERIC_ID)
    && exact(baseline.head_sha, COMMIT_SHA), "legacy baseline run identity is invalid");
  fail(baseline.fresh_runner === true && baseline.outcome === "SUCCEEDED", "legacy baseline did not succeed freshly");
  fail(baseline.revision === revisions.legacy_1, "legacy baseline revision does not match legacy_1");
  fail(exact(baseline.release_marker, /^[a-z0-9][a-z0-9-]{0,19}$/), "legacy baseline release marker is invalid");
  requireSources(baseline.source_ids,
    ["GITHUB_RUN", "GITHUB_ENVIRONMENT_REVIEW", "GCP_IAM_KEY", "CLOUD_RUN_REVISION"], "legacy baseline");
  fail(baseline.source_ids?.length === 4, "legacy baseline requires exactly four sources");

  return { evidence, used, requireSources };
}

function preDisableFragmentOf(manifest) {
  return Object.fromEntries([...PRE_DISABLE_TOP_LEVEL].map((field) => [field, manifest?.[field]]));
}

export function verifyK0PreDisableFragment(fragment, evidenceItems) {
  const errors = [];
  const { evidence, used } = validatePreDisableFragment(fragment, evidenceItems, errors);
  for (const id of evidence.keys()) {
    if (!used.has(id)) errors.push(`${id} is unreferenced pre-disable evidence`);
  }
  if (CREDENTIAL.test(JSON.stringify({ fragment, evidence: evidenceItems }))) {
    errors.push("pre-disable fragment contains credential-shaped material");
  }
  return { ok: errors.length === 0, errors };
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
  fail(manifest.version === 3, "version must be 3");
  fail(isRfc3339(manifest.assembled_at), "assembled_at is invalid");

  const { evidence, used, requireSources } = validatePreDisableFragment(
    preDisableFragmentOf(manifest),
    manifest.evidence,
    errors,
  );
  const scope = manifest.scope ?? {};
  const revisions = manifest.revisions ?? {};
  const checkpoint = manifest.checkpoint ?? {};
  fail(Object.keys(checkpoint).length === CHECKPOINT_FIELDS.size
    && Object.keys(checkpoint).every((key) => CHECKPOINT_FIELDS.has(key)), "checkpoint fields are invalid");
  requireSources([checkpoint.source_id], ["GITHUB_EVIDENCE_CHECKPOINT"], "evidence checkpoint");
  requireSources([revisions.forbidden_after_source_id], ["CLOUD_RUN_REVISION"], "forbidden-after revision");

  const disable = manifest.disable ?? {};
  fail(Object.keys(disable).every((key) => DISABLE_FIELDS.has(key)), "key disable has unknown fields");
  fail(disable.key_id === scope.key_id, "disabled key does not match scope");
  fail(disable.observed_disabled === true && exact(disable.human_actor, EMAIL)
    && !SERVICE_ACCOUNT.test(disable.human_actor), "human key disable is not proven");
  fail(exact(disable.service_account_unique_id, NUMERIC_ID), "disable service-account identity is invalid");
  fail(disable.service_account_unique_id === scope.service_account_unique_id, "disable service-account identity does not match scope");
  fail(present(disable.audit_insert_id), "disable audit insert ID is invalid");
  fail(isRfc3339(disable.audit_timestamp), "disable audit timestamp is invalid");
  requireSources(disable.source_ids, ["GCP_IAM_KEY", "GCP_AUDIT_ENTRY"], "key disable");
  fail(disable.source_ids?.length === 2, "key disable requires exactly two sources");

  const legacy = manifest.legacy_after_disable ?? {};
  fail(Object.keys(legacy).every((key) => LEGACY_FIELDS.has(key)), "legacy denial has unknown fields");
  fail(exact(legacy.run_id, NUMERIC_ID) && exact(legacy.run_attempt, NUMERIC_ID)
    && exact(legacy.head_sha, COMMIT_SHA), "legacy denial run identity is invalid");
  fail(legacy.fresh_runner === true && legacy.fresh_online_request === true, "legacy denial was not fresh and online");
  fail(legacy.outcome === "DENIED", "fresh legacy authentication did not fail");
  requireSources(legacy.source_ids, ["GITHUB_RUN", "GOOGLE_AUTH_RESULT"], "legacy denial");
  fail(legacy.source_ids?.length === 2, "legacy denial requires exactly two sources");

  const post = manifest.post_disable ?? {};
  fail(Object.keys(post).every((key) => POST_FIELDS.has(key)), "post-disable WIF has unknown fields");
  fail(exact(post.run_id, NUMERIC_ID) && exact(post.run_attempt, NUMERIC_ID)
    && exact(post.head_sha, COMMIT_SHA), "post-disable WIF run identity is invalid");
  fail(post.fresh_runner === true && post.outcome === "SUCCEEDED", "post-disable WIF did not succeed freshly");
  fail(post.revision === revisions.wif_2, "post-disable revision does not match wif_2");
  fail(exact(post.release_marker, /^[a-z0-9][a-z0-9-]{0,19}$/), "post-disable release marker is invalid");
  requireSources(post.source_ids, ["GITHUB_RUN", "GITHUB_ENVIRONMENT_REVIEW", "GCP_WIF_AUDIT_LOG", "CLOUD_RUN_REVISION"], "post-disable WIF");
  fail(post.source_ids?.length === 4, "post-disable WIF requires exactly four sources");

  fail(Object.keys(manifest.leak_scan ?? {}).every((key) => LEAK_FIELDS.has(key)), "leak scan has unknown fields");
  fail(manifest.leak_scan?.outcome === "CLEAN", "credential leak scan is not clean");
  requireSources(manifest.leak_scan?.source_ids, ["LEAK_SCAN"], "leak scan");
  fail(manifest.leak_scan?.source_ids?.length === 1, "leak scan requires exactly one source");
  fail(Array.isArray(manifest.limitations) && manifest.limitations.length > 0 && manifest.limitations.every(present), "limitations must be a non-empty array of bounded strings");
  for (const id of evidence.keys()) fail(used.has(id), `${id} is unreferenced evidence`);
  fail(!CREDENTIAL.test(JSON.stringify(manifest)), "manifest contains credential-shaped material");
  return { ok: errors.length === 0, errors };
}

async function main(path) {
  if (!path) throw new Error("Usage: node src/k0-manifest.mjs <manifest.json>");
  const { verifyK0EvidenceSemantics } = await import("./k0-evidence-semantics.mjs");
  const manifestPath = resolve(path);
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const result = verifyK0Manifest(manifest);
  if (!result.ok) throw new Error(result.errors.join("\n"));
  const artifacts = await verifyK0EvidenceSemantics(
    manifest,
    (id) => readFile(join(dirname(manifestPath), "artifacts", `${id}.json`)),
  );
  if (!artifacts.ok) throw new Error(artifacts.errors.join("\n"));
  process.stdout.write("K0 manifest and evidence artifacts verified\n");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv[2]).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
