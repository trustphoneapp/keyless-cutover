import { createHash } from "node:crypto";

import { canonicalJson, verifyEvidenceArtifacts } from "./evidence-artifact.mjs";
import { createCredentialScan } from "./credential-scan.mjs";
import { computePreexistingWifParityHash } from "./gcp-evidence.mjs";
import { parseGitHubEvidenceCheckpointReceipt, parseWifAuditEvidence } from "./k0-evidence-normalizer.mjs";
import { verifyK0PreDisableFragment } from "./k0-manifest.mjs";
import { isRfc3339, timestampAtOrBefore, timestampBefore, timestampNanoseconds } from "./rfc3339.mjs";

const SHA256 = /^[a-f0-9]{64}$/;
const FINAL_SCAN_LOCATOR = "credential-scan:final-bundle";
const KEY_ID = /^[a-f0-9]{40}$/;
const COMMIT_SHA = /^[a-f0-9]{40}$/;
const NUMERIC = /^\d+$/;
const CHALLENGE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REVISION = /^[a-z][a-z0-9-]{0,62}$/;
const REGION = /^[a-z]+-[a-z]+\d$/;
const WORKFLOW = /^\.github\/workflows\/[A-Za-z0-9._/-]+\.ya?ml$/;
const SERVICE_ACCOUNT = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;
const CHECKPOINT_FIELDS = new Set([
  "owner_id", "repository_id", "collected_at", "protection", "pull", "receipt", "archive", "run", "check",
]);
const CHECKPOINT_PROTECTION_FIELDS = new Set([
  "branch", "required_status_checks_strict", "required_check_name", "required_check_app_id",
  "required_approving_review_count", "dismiss_stale_reviews", "require_last_push_approval", "enforce_admins",
  "required_linear_history",
]);
const CHECKPOINT_PULL_FIELDS = new Set([
  "number", "head_sha", "merge_sha", "author_id", "reviewer_id", "review_commit_sha", "reviewed_at", "merged_at",
]);
const CHECKPOINT_RECEIPT_FIELDS = new Set(["path", "blob_sha", "sha256", "bytes_base64"]);
const CHECKPOINT_ARCHIVE_FIELDS = new Set([
  "path", "blob_sha", "sha256", "ledger_sha256", "artifact_bytes_sha256", "sealed_at", "transaction_id", "nonce",
]);
const CHECKPOINT_RUN_FIELDS = new Set([
  "run_id", "run_attempt", "head_sha", "workflow_path", "event", "ref", "status", "conclusion", "started_at", "completed_at",
]);
const CHECKPOINT_CHECK_FIELDS = new Set([
  "name", "app_id", "app_slug", "head_sha", "status", "conclusion", "started_at", "completed_at", "details_url",
]);
const DATA_FIELDS = {
  GITHUB_RUN: new Set(["run_id", "run_attempt", "head_sha", "workflow_path", "workflow_ref", "workflow_blob_sha", "workflow_sha256", "owner_id", "repository_id", "actor_id", "event", "ref", "environment", "conclusion", "runner_environment", "started_at", "release_marker"]),
  GITHUB_ENVIRONMENT_REVIEW: new Set(["run_id", "run_attempt", "head_sha", "environment", "actor_id", "reviewer_id", "state"]),
  GITHUB_PULL_REQUEST: new Set(["number", "head_sha", "merge_sha", "workflow_path", "workflow_blob_sha", "workflow_sha256", "owner_id", "repository_id", "author_id", "reviewer_id", "review_commit_sha", "reviewed_at", "merged_at", "merged", "reviewed"]),
  PROOFV2_ARTIFACT: new Set(["challenge_id", "proof_digest", "key_id", "run_id", "run_attempt", "head_sha", "verified", "consumed"]),
  PROOFV2_CHALLENGE_STATE: new Set([
    "version", "status", "verified", "consumed", "replay_rejected", "replay_evidence",
    "migration_id", "challenge_id", "proof_digest", "key_id", "owner_id", "repository_id",
    "workflow_path", "event_name", "ref", "environment", "client_email", "run_id", "run_attempt",
    "head_sha", "run_started_at", "issued_at", "expires_at", "consumed_at", "update_time",
    "receipt_sha256",
  ]),
  GCP_IAM_KEY: new Set(["name", "key_id", "key_type", "algorithm", "disabled", "project_id", "project_number", "service_account_email", "service_account_unique_id"]),
  GCP_WIF_PROVIDER: new Set(["name", "config_hash", "state", "project_id", "project_number", "service_account_email", "service_account_unique_id"]),
  GCP_IAM_POLICY: new Set(["policy_hash", "iam_diff_hash", "etag", "no_added_downstream_permissions", "project_id", "project_number", "service_account_email", "service_account_unique_id"]),
  GCP_WIF_PARITY: new Set([
    "mode", "provider", "provider_state", "provider_config_hash", "provider_before_hash", "provider_after_hash",
    "service_account_policy_before_hash", "service_account_policy_after_hash",
    "service_account_etag_sha256", "allowed_policy_before_hash", "allowed_policy_after_hash", "allowed_etag_sha256",
    "forbidden_policy_before_hash", "forbidden_policy_after_hash", "forbidden_etag_sha256",
    "expected_binding_hash", "no_added_downstream_permissions", "no_forbidden_access",
    "owner_id", "repository_id", "project_id", "project_number", "service_account_email", "service_account_unique_id",
    "region", "allowed_service", "forbidden_service",
    "observed_before_at", "observed_after_at", "parity_hash",
  ]),
  STS_CLIENT_RESULT: new Set(["hostile_id", "run_id", "run_attempt", "head_sha", "outcome", "reached_sts", "error_category", "denied_at", "log_sha256"]),
  CLOUD_RUN_IAM_RESULT: new Set(["hostile_id", "run_id", "run_attempt", "head_sha", "outcome", "reached_cloud_run", "target", "denied_at", "log_sha256"]),
  CLOUD_RUN_REVISION: new Set(["project_id", "region", "service", "revision", "create_time", "release_marker", "image_digest"]),
  GCP_AUDIT_ENTRY: new Set(["method_name", "resource_name", "principal_email", "key_id", "service_account_email", "service_account_unique_id", "project_id", "project_number", "insert_id", "timestamp", "status"]),
  GOOGLE_AUTH_RESULT: new Set(["key_id", "run_id", "run_attempt", "head_sha", "owner_id", "repository_id", "workflow_path", "workflow_ref", "ref", "outcome", "fresh_runner", "fresh_online_request", "reached_google", "rejection_category", "rejected_at", "log_sha256"]),
  GCP_WIF_AUDIT_LOG: new Set(["entries"]),
  GITHUB_EVIDENCE_CHECKPOINT: CHECKPOINT_FIELDS,
  LEAK_SCAN: new Set(["outcome", "scanner", "scope_hash", "artifact_count"]),
};

function string(value, pattern) {
  return typeof value === "string" && value.length > 0 && value.length <= 2048 && (!pattern || pattern.test(value));
}

function evidenceJsonPath(value) {
  const segments = typeof value === "string" ? value.split("/") : [];
  return typeof value === "string" && value.length <= 256
    && segments[0] === "docs" && segments[1] === "evidence"
    && segments.length >= 3 && segments.every((segment) => /^[A-Za-z0-9._-]+$/.test(segment)
      && segment !== "." && segment !== "..")
    && /^[A-Za-z0-9._-]+\.json$/.test(segments.at(-1));
}

function object(value) {
  return value && typeof value === "object" && !Array.isArray(value);
}

function exactFields(value, fields) {
  return object(value) && Object.keys(value).length === fields.size
    && Object.keys(value).every((key) => fields.has(key));
}

function validateArtifactData(kind, data, fail, id) {
  const fields = DATA_FIELDS[kind];
  fail(fields && exactFields(data, fields), `${id} ${kind} data fields are invalid`);
  if (!fields || !exactFields(data, fields)) return;
  if (kind === "GITHUB_RUN") {
    fail(string(data.run_id, NUMERIC) && string(data.run_attempt, NUMERIC), `${id} GitHub run identity is invalid`);
    fail(string(data.head_sha, COMMIT_SHA) && string(data.workflow_path, WORKFLOW) && string(data.workflow_ref)
      && string(data.workflow_blob_sha, COMMIT_SHA) && string(data.workflow_sha256, SHA256), `${id} GitHub workflow identity is invalid`);
    fail(string(data.owner_id, NUMERIC) && string(data.repository_id, NUMERIC)
      && string(data.actor_id, NUMERIC), `${id} GitHub repository identity is invalid`);
    fail(string(data.event) && string(data.ref) && string(data.environment)
      && ["success", "failure"].includes(data.conclusion), `${id} GitHub run result is invalid`);
    fail(data.runner_environment === "github-hosted" && isRfc3339(data.started_at), `${id} GitHub runner evidence is invalid`);
    fail(data.release_marker === null || /^[a-z0-9][a-z0-9-]{0,19}$/.test(data.release_marker), `${id} release marker is invalid`);
  } else if (kind === "GITHUB_ENVIRONMENT_REVIEW") {
    fail(string(data.run_id, NUMERIC) && string(data.run_attempt, NUMERIC) && string(data.head_sha, COMMIT_SHA)
      && string(data.environment), `${id} environment review scope is invalid`);
    fail(string(data.actor_id, NUMERIC) && string(data.reviewer_id, NUMERIC)
      && data.actor_id !== data.reviewer_id, `${id} environment review is not independent`);
    fail(data.state === "approved", `${id} environment review was not approved`);
  } else if (kind === "GITHUB_PULL_REQUEST") {
    fail(Number.isInteger(data.number) && data.number > 0 && string(data.head_sha, COMMIT_SHA)
      && string(data.merge_sha, COMMIT_SHA) && string(data.workflow_blob_sha, COMMIT_SHA)
      && string(data.workflow_sha256, SHA256) && string(data.workflow_path, WORKFLOW), `${id} pull request identity is invalid`);
    fail(string(data.owner_id, NUMERIC) && string(data.repository_id, NUMERIC)
      && string(data.author_id, NUMERIC) && string(data.reviewer_id, NUMERIC)
      && data.author_id !== data.reviewer_id && data.review_commit_sha === data.head_sha
      && isRfc3339(data.reviewed_at) && isRfc3339(data.merged_at)
      && timestampAtOrBefore(data.reviewed_at, data.merged_at)
      && data.merged === true && data.reviewed === true,
    `${id} pull request was not independently reviewed and merged`);
  } else if (kind === "PROOFV2_ARTIFACT") {
    fail(string(data.challenge_id) && string(data.proof_digest, SHA256) && string(data.key_id, KEY_ID)
      && string(data.run_id, NUMERIC) && string(data.run_attempt, NUMERIC)
      && string(data.head_sha, COMMIT_SHA), `${id} ProofV2 data is invalid`);
    fail(data.verified === true && data.consumed === true, `${id} ProofV2 was not verified and consumed`);
  } else if (kind === "PROOFV2_CHALLENGE_STATE") {
    fail(data.version === 3 && data.status === "CONSUMED" && data.verified === true
      && data.consumed === true && data.replay_rejected === true
      && data.replay_evidence === "ORIGINAL_OPERATOR_RECEIPT_ONLY", `${id} ProofV2 challenge state is not consumed`);
    fail(string(data.migration_id) && string(data.challenge_id, CHALLENGE_ID)
      && string(data.proof_digest, SHA256) && string(data.key_id, KEY_ID)
      && string(data.owner_id, NUMERIC) && string(data.repository_id, NUMERIC)
      && string(data.workflow_path, WORKFLOW) && data.event_name === "workflow_dispatch"
      && data.ref === "refs/heads/main" && data.environment === "production"
      && string(data.client_email, SERVICE_ACCOUNT) && string(data.run_id, NUMERIC)
      && string(data.run_attempt, NUMERIC) && string(data.head_sha, COMMIT_SHA)
      && string(data.receipt_sha256, SHA256), `${id} ProofV2 challenge state identity is invalid`);
    fail(isRfc3339(data.run_started_at) && isRfc3339(data.issued_at) && isRfc3339(data.expires_at)
      && isRfc3339(data.consumed_at) && isRfc3339(data.update_time)
      && timestampAtOrBefore(data.issued_at, data.run_started_at)
      && timestampAtOrBefore(data.run_started_at, data.consumed_at)
      && timestampBefore(data.consumed_at, data.expires_at)
      && timestampAtOrBefore(data.consumed_at, data.update_time), `${id} ProofV2 challenge state timeline is invalid`);
  } else if (kind === "GCP_IAM_KEY") {
    fail(string(data.key_id, KEY_ID) && string(data.name), `${id} Google key identity is invalid`);
    fail(data.key_type === "USER_MANAGED" && data.algorithm === "KEY_ALG_RSA_2048"
      && typeof data.disabled === "boolean", `${id} Google key state is invalid`);
    fail(string(data.project_id) && string(data.project_number, NUMERIC) && string(data.service_account_email)
      && string(data.service_account_unique_id, NUMERIC), `${id} Google key scope is invalid`);
    const keyNames = new Set([
      `projects/-/serviceAccounts/${data.service_account_email}/keys/${data.key_id}`,
      `projects/${data.project_id}/serviceAccounts/${data.service_account_email}/keys/${data.key_id}`,
      `projects/-/serviceAccounts/${data.service_account_unique_id}/keys/${data.key_id}`,
      `projects/${data.project_id}/serviceAccounts/${data.service_account_unique_id}/keys/${data.key_id}`,
    ]);
    fail(keyNames.has(data.name), `${id} Google key resource is invalid`);
  } else if (kind === "GCP_WIF_PROVIDER") {
    fail(string(data.name) && string(data.config_hash, SHA256) && data.state === "ACTIVE", `${id} WIF provider data is invalid`);
    fail(string(data.project_id) && string(data.project_number, NUMERIC) && string(data.service_account_email)
      && string(data.service_account_unique_id, NUMERIC), `${id} WIF provider scope is invalid`);
  } else if (kind === "GCP_IAM_POLICY") {
    fail(string(data.policy_hash, SHA256) && string(data.iam_diff_hash, SHA256) && string(data.etag)
      && data.no_added_downstream_permissions === true, `${id} IAM policy data is invalid`);
    fail(string(data.project_id) && string(data.project_number, NUMERIC) && string(data.service_account_email)
      && string(data.service_account_unique_id, NUMERIC), `${id} IAM policy scope is invalid`);
  } else if (kind === "GCP_WIF_PARITY") {
    const hashes = [
      data.provider_config_hash, data.provider_before_hash, data.provider_after_hash,
      data.service_account_policy_before_hash, data.service_account_policy_after_hash,
      data.allowed_policy_before_hash, data.allowed_policy_after_hash,
      data.forbidden_policy_before_hash, data.forbidden_policy_after_hash,
      data.service_account_etag_sha256, data.allowed_etag_sha256, data.forbidden_etag_sha256,
      data.expected_binding_hash, data.parity_hash,
    ];
    fail(data.mode === "PREEXISTING_EXACT" && data.provider_state === "ACTIVE"
      && string(data.provider) && hashes.every((value) => string(value, SHA256))
      && data.no_added_downstream_permissions === true && data.no_forbidden_access === true,
    `${id} WIF parity result is invalid`);
    fail(string(data.owner_id, NUMERIC) && string(data.repository_id, NUMERIC)
      && string(data.project_id) && string(data.project_number, NUMERIC)
      && string(data.service_account_email, SERVICE_ACCOUNT)
      && string(data.service_account_unique_id, NUMERIC)
      && string(data.region, REGION)
      && string(data.allowed_service, REVISION) && string(data.forbidden_service, REVISION)
      && data.allowed_service !== data.forbidden_service, `${id} WIF parity scope is invalid`);
    fail(data.provider_before_hash === data.provider_after_hash
      && data.service_account_policy_before_hash === data.service_account_policy_after_hash
      && data.allowed_policy_before_hash === data.allowed_policy_after_hash
      && data.forbidden_policy_before_hash === data.forbidden_policy_after_hash,
    `${id} WIF parity contains policy drift`);
    const pool = data.provider?.replace(/\/providers\/[a-z0-9-]+$/, "");
    const expectedMember = `principalSet://iam.googleapis.com/${pool}/attribute.repo_id/${data.repository_id}`;
    const expectedBindingHash = createHash("sha256").update(canonicalJson({
      resource: data.service_account_email,
      role: "roles/iam.workloadIdentityUser",
      member: expectedMember,
    })).digest("hex");
    fail(data.provider?.startsWith(`projects/${data.project_number}/locations/global/workloadIdentityPools/`)
      && data.expected_binding_hash === expectedBindingHash, `${id} WIF parity binding is invalid`);
    fail(isRfc3339(data.observed_before_at) && isRfc3339(data.observed_after_at)
      && timestampBefore(data.observed_before_at, data.observed_after_at), `${id} WIF parity timeline is invalid`);
    try {
      fail(computePreexistingWifParityHash(data) === data.parity_hash, `${id} WIF parity hash is invalid`);
    } catch {
      fail(false, `${id} WIF parity hash is invalid`);
    }
  } else if (kind === "STS_CLIENT_RESULT") {
    fail(/^H[1-7]$/.test(data.hostile_id) && string(data.run_id, NUMERIC)
      && string(data.run_attempt, NUMERIC) && string(data.head_sha, COMMIT_SHA), `${id} STS hostile identity is invalid`);
    fail(data.outcome === "DENIED" && data.reached_sts === true
      && ["WIF_CONDITION_DENIED", "AUDIENCE_DENIED"].includes(data.error_category)
      && isRfc3339(data.denied_at) && string(data.log_sha256, SHA256), `${id} STS denial is invalid`);
  } else if (kind === "CLOUD_RUN_IAM_RESULT") {
    fail(data.hostile_id === "H8" && string(data.run_id, NUMERIC)
      && string(data.run_attempt, NUMERIC) && string(data.head_sha, COMMIT_SHA)
      && string(data.target, REVISION), `${id} Cloud Run hostile identity is invalid`);
    fail(data.outcome === "DENIED" && data.reached_cloud_run === true && isRfc3339(data.denied_at)
      && string(data.log_sha256, SHA256), `${id} Cloud Run denial is invalid`);
  } else if (kind === "CLOUD_RUN_REVISION") {
    fail(string(data.project_id) && string(data.region)
      && string(data.service, REVISION) && string(data.revision, REVISION) && isRfc3339(data.create_time)
      && /^[a-z0-9][a-z0-9-]{0,19}$/.test(data.release_marker)
      && /^sha256:[a-f0-9]{64}$/.test(data.image_digest), `${id} Cloud Run revision data is invalid`);
  } else if (kind === "GCP_AUDIT_ENTRY") {
    fail(data.method_name === "google.iam.admin.v1.DisableServiceAccountKey" && data.status === "SUCCEEDED"
      && string(data.resource_name) && string(data.principal_email) && string(data.key_id, KEY_ID)
      && string(data.service_account_email) && string(data.service_account_unique_id, NUMERIC)
      && data.resource_name === `projects/-/serviceAccounts/${data.service_account_unique_id}/keys/${data.key_id}`
      && string(data.project_id) && string(data.project_number, NUMERIC) && string(data.insert_id)
      && isRfc3339(data.timestamp), `${id} audit entry data is invalid`);
  } else if (kind === "GOOGLE_AUTH_RESULT") {
    fail(string(data.key_id, KEY_ID) && string(data.run_id, NUMERIC) && string(data.run_attempt, NUMERIC)
      && string(data.head_sha, COMMIT_SHA) && string(data.owner_id, NUMERIC) && string(data.repository_id, NUMERIC)
      && string(data.workflow_path, WORKFLOW) && string(data.workflow_ref) && string(data.ref), `${id} legacy-auth identity is invalid`);
    fail(data.outcome === "DENIED" && data.fresh_runner === true && data.fresh_online_request === true
      && data.reached_google === true && data.rejection_category === "DISABLED_OR_INVALID_KEY"
      && isRfc3339(data.rejected_at) && string(data.log_sha256, SHA256), `${id} legacy denial is invalid`);
  } else if (kind === "GCP_WIF_AUDIT_LOG") {
    try {
      parseWifAuditEvidence(Buffer.from(canonicalJson(data)));
    } catch {
      fail(false, `${id} WIF audit evidence is invalid`);
    }
  } else if (kind === "GITHUB_EVIDENCE_CHECKPOINT") {
    const protection = data.protection;
    const pull = data.pull;
    const receipt = data.receipt;
    const archive = data.archive;
    const run = data.run;
    const check = data.check;
    fail(string(data.owner_id, NUMERIC) && string(data.repository_id, NUMERIC)
      && isRfc3339(data.collected_at), `${id} checkpoint repository identity is invalid`);
    fail(exactFields(protection, CHECKPOINT_PROTECTION_FIELDS) && protection?.branch === "main"
      && protection?.required_status_checks_strict === true && protection?.required_check_name === "test"
      && protection?.required_check_app_id === "15368" && protection?.required_approving_review_count === 1
      && protection?.dismiss_stale_reviews === true && protection?.require_last_push_approval === true
      && protection?.enforce_admins === true && protection?.required_linear_history === true,
    `${id} checkpoint branch protection is invalid`);
    fail(exactFields(pull, CHECKPOINT_PULL_FIELDS) && Number.isInteger(pull?.number) && pull.number > 0
      && string(pull?.head_sha, COMMIT_SHA) && string(pull?.merge_sha, COMMIT_SHA)
      && string(pull?.author_id, NUMERIC) && string(pull?.reviewer_id, NUMERIC)
      && pull?.author_id !== pull?.reviewer_id && pull?.review_commit_sha === pull?.head_sha
      && isRfc3339(pull?.reviewed_at) && isRfc3339(pull?.merged_at)
      && timestampAtOrBefore(pull?.reviewed_at, pull?.merged_at), `${id} checkpoint pull request is invalid`);
    fail(exactFields(receipt, CHECKPOINT_RECEIPT_FIELDS)
      && evidenceJsonPath(receipt?.path)
      && string(receipt?.blob_sha, COMMIT_SHA) && string(receipt?.sha256, SHA256)
      && typeof receipt?.bytes_base64 === "string" && receipt.bytes_base64.length > 0,
    `${id} checkpoint receipt identity is invalid`);
    try {
      const parsed = parseGitHubEvidenceCheckpointReceipt(Buffer.from(receipt?.bytes_base64 ?? "", "base64"));
      fail(parsed.receipt_bytes_base64 === receipt?.bytes_base64
        && parsed.receipt_blob_sha === receipt?.blob_sha && parsed.receipt_sha256 === receipt?.sha256,
      `${id} checkpoint receipt bytes do not match`);
    } catch {
      fail(false, `${id} checkpoint receipt bytes are invalid`);
    }
    fail(exactFields(archive, CHECKPOINT_ARCHIVE_FIELDS)
      && evidenceJsonPath(archive?.path)
      && archive?.path !== receipt?.path && string(archive?.blob_sha, COMMIT_SHA)
      && string(archive?.sha256, SHA256) && string(archive?.ledger_sha256, SHA256)
      && string(archive?.artifact_bytes_sha256, SHA256) && isRfc3339(archive?.sealed_at)
      && /^[a-z0-9][a-z0-9-]{0,63}$/.test(archive?.transaction_id ?? "")
      && /^[A-Za-z0-9_-]{16,128}$/.test(archive?.nonce ?? "")
      && timestampAtOrBefore(archive?.sealed_at, pull?.reviewed_at),
    `${id} checkpoint archive identity is invalid`);
    fail(exactFields(run, CHECKPOINT_RUN_FIELDS) && string(run?.run_id, NUMERIC)
      && string(run?.run_attempt, NUMERIC) && run?.head_sha === pull?.merge_sha
      && run?.workflow_path === ".github/workflows/ci.yml" && run?.event === "push"
      && run?.ref === "refs/heads/main" && run?.status === "completed" && run?.conclusion === "success"
      && isRfc3339(run?.started_at) && isRfc3339(run?.completed_at)
      && timestampAtOrBefore(pull?.merged_at, run?.started_at)
      && timestampAtOrBefore(run?.started_at, run?.completed_at), `${id} checkpoint main push run is invalid`);
    fail(exactFields(check, CHECKPOINT_CHECK_FIELDS) && check?.name === "test"
      && check?.app_id === "15368" && check?.app_slug === "github-actions"
      && check?.head_sha === pull?.merge_sha && check?.status === "completed" && check?.conclusion === "success"
      && isRfc3339(check?.started_at) && isRfc3339(check?.completed_at)
      && /^https:\/\/github\.com\/[A-Za-z0-9-]+\/[A-Za-z0-9._-]+\/actions\/runs\/\d+\/job\/\d+$/.test(check?.details_url ?? "")
      && check?.details_url.includes(`/actions/runs/${run?.run_id}/job/`)
      && timestampAtOrBefore(run?.started_at, check?.started_at)
      && timestampAtOrBefore(check?.started_at, check?.completed_at)
      && timestampAtOrBefore(check?.completed_at, run?.completed_at)
      && timestampAtOrBefore(run?.completed_at, data.collected_at), `${id} checkpoint required check is invalid`);
    fail(timestampBefore(pull?.reviewed_at, pull?.merged_at)
      && timestampBefore(pull?.reviewed_at, run?.started_at)
      && timestampBefore(pull?.reviewed_at, check?.started_at)
      && timestampBefore(pull?.reviewed_at, data.collected_at),
    `${id} checkpoint archive review timeline is invalid`);
  } else if (kind === "LEAK_SCAN") {
    fail(data.outcome === "CLEAN" && data.scanner === "KEYLESS_CREDENTIAL_SCAN_V1"
      && string(data.scope_hash, SHA256) && Number.isInteger(data.artifact_count)
      && data.artifact_count > 0 && data.artifact_count <= 100, `${id} leak scan data is invalid`);
  }
}

const PRE_DISABLE_FIELDS = [
  "scope", "revisions", "approved_workflows", "legacy_baseline", "proof", "cutover", "wif", "hostile_tests",
];

function preDisableFragment(manifest) {
  return Object.fromEntries(PRE_DISABLE_FIELDS.map((field) => [field, manifest?.[field]]));
}

function preDisableSourceIds(manifest) {
  return new Set([
    ...manifest.legacy_baseline.source_ids,
    ...manifest.proof.source_ids,
    ...manifest.cutover.source_ids,
    ...manifest.wif.source_ids,
    ...Object.values(manifest.approved_workflows).map(({ source_id: sourceId }) => sourceId),
    ...manifest.hostile_tests.flatMap(({ source_ids: sourceIds }) => sourceIds),
  ]);
}

function occurrenceValues(manifest, entry, data) {
  if (entry?.kind === "GITHUB_RUN") return [data?.started_at];
  if (entry?.kind === "PROOFV2_CHALLENGE_STATE") {
    return [data?.issued_at, data?.run_started_at, data?.consumed_at, data?.update_time];
  }
  if (entry?.kind === "GCP_WIF_PARITY") return [data?.observed_before_at, data?.observed_after_at];
  if (entry?.kind === "GITHUB_PULL_REQUEST") return [data?.reviewed_at, data?.merged_at];
  if (entry?.kind === "STS_CLIENT_RESULT" || entry?.kind === "CLOUD_RUN_IAM_RESULT") return [data?.denied_at];
  if (entry?.kind === "GCP_AUDIT_ENTRY") return [data?.timestamp];
  if (entry?.kind === "GOOGLE_AUTH_RESULT") return [data?.rejected_at];
  if (entry?.kind === "CLOUD_RUN_REVISION"
      && [manifest.revisions.legacy_1, manifest.revisions.wif_1, manifest.revisions.wif_2].includes(data?.revision)) {
    return [data?.create_time];
  }
  if (entry?.kind === "GCP_WIF_AUDIT_LOG") {
    try {
      const audit = parseWifAuditEvidence(Buffer.from(canonicalJson(data)));
      return [audit.exchanged_at, audit.authenticated_at];
    } catch {
      return [];
    }
  }
  return [];
}

function validatePreDisableSemantics(manifest, entries, artifacts, observedAt, fail) {
  const dataOfKind = (ids, kind) => ids
    .filter((id) => entries.get(id)?.kind === kind)
    .map((id) => artifacts.get(id)?.data);
  const entryOfKind = (ids, kind) => ids
    .filter((id) => entries.get(id)?.kind === kind)
    .map((id) => ({ entry: entries.get(id), data: artifacts.get(id)?.data }));
  const gcpScopeMatches = (data) => data?.project_id === manifest.scope.project_id
    && data?.project_number === manifest.scope.project_number
    && data?.service_account_email === manifest.scope.service_account_email
    && data?.service_account_unique_id === manifest.scope.service_account_unique_id;
  const revisionScopeMatches = (data) => data?.project_id === manifest.scope.project_id
    && data?.region === manifest.scope.region;
  const runMatches = (run, claim, workflowPath = manifest.scope.workflow_path) => run?.run_id === claim.run_id
    && run?.run_attempt === claim.run_attempt && run?.head_sha === claim.head_sha
    && run?.owner_id === manifest.scope.owner_id && run?.repository_id === manifest.scope.repository_id
    && run?.workflow_path === workflowPath
    && run?.workflow_ref?.endsWith(`/${workflowPath}@refs/heads/main`)
    && run?.ref === "refs/heads/main" && run?.environment === "production"
    && run?.runner_environment === "github-hosted" && run?.conclusion === "success";
  const reviewMatches = (review, run) => review?.run_id === run?.run_id
    && review?.run_attempt === run?.run_attempt && review?.head_sha === run?.head_sha
    && review?.environment === run?.environment && review?.actor_id === run?.actor_id
    && review?.reviewer_id !== run?.actor_id && review?.state === "approved";

  const forbiddenBeforeId = manifest.revisions.forbidden_before_source_id;
  const forbiddenAfterHostileId = manifest.revisions.forbidden_after_hostile_source_id;
  const forbiddenBefore = artifacts.get(forbiddenBeforeId)?.data;
  const forbiddenAfterHostile = artifacts.get(forbiddenAfterHostileId)?.data;
  fail(forbiddenBefore?.service === manifest.scope.forbidden_service
    && forbiddenBefore?.revision === manifest.revisions.forbidden_before && revisionScopeMatches(forbiddenBefore),
  "forbidden-before revision artifact does not match");
  fail(forbiddenAfterHostile?.service === manifest.scope.forbidden_service
    && forbiddenAfterHostile?.revision === manifest.revisions.forbidden_after && revisionScopeMatches(forbiddenAfterHostile),
  "forbidden-after-hostile revision artifact does not match");
  fail(timestampBefore(observedAt.get(forbiddenBeforeId), observedAt.get(forbiddenAfterHostileId)),
    "forbidden revision observations are stale or out of order");

  const proofData = dataOfKind(manifest.proof.source_ids, "PROOFV2_ARTIFACT");
  const proofStates = entryOfKind(manifest.proof.source_ids, "PROOFV2_CHALLENGE_STATE");
  const proofKeys = dataOfKind(manifest.proof.source_ids, "GCP_IAM_KEY");
  fail(proofKeys.some((data) => data?.key_id === manifest.scope.key_id && data?.disabled === false
    && gcpScopeMatches(data)), "ProofV2 key was not observed active in scope");
  const proofRuns = dataOfKind(manifest.proof.source_ids, "GITHUB_RUN");
  const proofReviews = dataOfKind(manifest.proof.source_ids, "GITHUB_ENVIRONMENT_REVIEW");
  const proofRun = proofRuns.find((run) => run?.owner_id === manifest.scope.owner_id
    && run?.repository_id === manifest.scope.repository_id && run?.workflow_path === manifest.scope.proof_workflow_path
    && run?.workflow_ref?.endsWith(`/${manifest.scope.proof_workflow_path}@refs/heads/main`)
    && run?.event === "workflow_dispatch" && run?.ref === "refs/heads/main" && run?.environment === "production"
    && run?.conclusion === "success" && run?.runner_environment === "github-hosted"
    && proofReviews.some((review) => review?.run_id === run.run_id && review?.run_attempt === run.run_attempt
      && review?.environment === "production"
      && review?.actor_id === run.actor_id && review?.reviewer_id !== run.actor_id
      && review?.head_sha === run.head_sha));
  fail(Boolean(proofRun), "ProofV2 run and review are not bound to scope");
  fail(proofData.some((data) => data?.challenge_id === manifest.proof.challenge_id
    && data?.proof_digest === manifest.proof.proof_digest && data?.key_id === manifest.scope.key_id
    && data?.run_id === proofRun?.run_id && data?.run_attempt === proofRun?.run_attempt
    && data?.head_sha === proofRun?.head_sha), "ProofV2 artifact does not match its exact run");
  const proofState = proofStates.find(({ entry, data }) => data?.challenge_id === manifest.proof.challenge_id
    && data?.proof_digest === manifest.proof.proof_digest && data?.key_id === manifest.scope.key_id
    && data?.receipt_sha256 === manifest.proof.receipt_sha256
    && data?.owner_id === manifest.scope.owner_id && data?.repository_id === manifest.scope.repository_id
    && data?.workflow_path === manifest.scope.proof_workflow_path && data?.event_name === "workflow_dispatch"
    && data?.ref === "refs/heads/main" && data?.environment === "production"
    && data?.client_email === manifest.scope.service_account_email
    && data?.run_id === proofRun?.run_id && data?.run_attempt === proofRun?.run_attempt
    && data?.head_sha === proofRun?.head_sha && data?.run_started_at === proofRun?.started_at
    && timestampAtOrBefore(data?.update_time, entry?.observed_at)
    && proofData.some((proof) => proof?.challenge_id === data.challenge_id
      && proof?.proof_digest === data.proof_digest && proof?.key_id === data.key_id
      && proof?.run_id === data.run_id && proof?.run_attempt === data.run_attempt
      && proof?.head_sha === data.head_sha && proof?.verified === true && proof?.consumed === true));
  fail(Boolean(proofState), "ProofV2 consumed challenge state does not match its proof, run, and scope");

  const hostileRun = (id) => dataOfKind(
    manifest.hostile_tests.find((hostile) => hostile.id === id)?.source_ids ?? [],
    "GITHUB_RUN",
  )[0];
  const baselineRuns = dataOfKind(manifest.legacy_baseline.source_ids, "GITHUB_RUN");
  const baselineReviews = dataOfKind(manifest.legacy_baseline.source_ids, "GITHUB_ENVIRONMENT_REVIEW");
  const baselineRun = baselineRuns.find((run) => runMatches(run, manifest.legacy_baseline)
    && run?.event === "workflow_dispatch"
    && run?.workflow_blob_sha === manifest.approved_workflows.baseline.workflow_blob_sha
    && run?.workflow_sha256 === manifest.approved_workflows.baseline.workflow_sha256
    && run?.release_marker === manifest.legacy_baseline.release_marker
    && baselineReviews.some((review) => reviewMatches(review, run)));
  const approvalMatches = (approval, ownerId, repositoryId, run) => {
    const pull = artifacts.get(approval.source_id)?.data;
    return entries.get(approval.source_id)?.kind === "GITHUB_PULL_REQUEST"
      && pull?.workflow_path === approval.workflow_path
      && pull?.workflow_blob_sha === approval.workflow_blob_sha
      && pull?.workflow_sha256 === approval.workflow_sha256
      && pull?.owner_id === ownerId && pull?.repository_id === repositoryId
      && pull?.merged === true && pull?.reviewed === true && pull?.author_id !== pull?.reviewer_id
      && (!run || timestampBefore(pull?.merged_at, run?.started_at));
  };
  for (const [role, approval] of Object.entries(manifest.approved_workflows)) {
    const run = role === "baseline" ? baselineRun
      : role === "h1" ? hostileRun("H1") : role === "h2" ? hostileRun("H2")
        : role === "h4" ? hostileRun("H4") : null;
    const ownerId = run?.owner_id ?? manifest.scope.owner_id;
    const repositoryId = run?.repository_id ?? manifest.scope.repository_id;
    fail(approvalMatches(approval, ownerId, repositoryId, run),
      `${approval.workflow_path} workflow approval does not match reviewed bytes`);
  }
  fail(Boolean(baselineRun), "legacy baseline GitHub run and independent review do not match");
  const baselineKeys = dataOfKind(manifest.legacy_baseline.source_ids, "GCP_IAM_KEY");
  fail(baselineKeys.some((data) => data?.key_id === manifest.scope.key_id && data?.disabled === false
    && gcpScopeMatches(data)), "legacy baseline active key does not match scope");
  const baselineRevisions = entryOfKind(manifest.legacy_baseline.source_ids, "CLOUD_RUN_REVISION");
  const baselineRevision = baselineRevisions.find(({ entry, data }) => data?.service === manifest.scope.allowed_service
    && data?.revision === manifest.revisions.legacy_1
    && data?.release_marker === manifest.legacy_baseline.release_marker
    && data?.revision.endsWith(`-${data.release_marker}`) && revisionScopeMatches(data)
    && timestampBefore(baselineRun?.started_at, data.create_time)
    && timestampBefore(data.create_time, entry?.observed_at));
  fail(Boolean(baselineRevision), "legacy baseline Cloud Run revision does not match its exact run and release marker");

  const pullRequests = dataOfKind(manifest.cutover.source_ids, "GITHUB_PULL_REQUEST");
  const cutoverPull = pullRequests.find((pull) => pull?.number === manifest.cutover.pr_number
    && pull?.head_sha === manifest.cutover.reviewed_head_sha && pull?.merge_sha === manifest.cutover.merge_sha
    && pull?.workflow_path === manifest.scope.workflow_path
    && pull?.workflow_blob_sha === manifest.cutover.workflow_blob_sha
    && pull?.workflow_sha256 === manifest.cutover.workflow_sha256
    && pull?.owner_id === manifest.scope.owner_id && pull?.repository_id === manifest.scope.repository_id);
  fail(Boolean(cutoverPull), "cutover pull request does not match");
  const wif1Runs = dataOfKind(manifest.cutover.source_ids, "GITHUB_RUN");
  const wif1Reviews = dataOfKind(manifest.cutover.source_ids, "GITHUB_ENVIRONMENT_REVIEW");
  const wif1Claim = {
    run_id: manifest.cutover.wif_1_run_id,
    run_attempt: manifest.cutover.wif_1_run_attempt,
    head_sha: manifest.cutover.wif_1_head_sha,
  };
  const wif1Run = wif1Runs.find((run) => runMatches(run, wif1Claim) && run?.event === "push"
    && run?.release_marker === manifest.cutover.wif_1_release_marker
    && run?.workflow_blob_sha === manifest.cutover.workflow_blob_sha
    && run?.workflow_sha256 === manifest.cutover.workflow_sha256
    && wif1Reviews.some((review) => reviewMatches(review, run)));
  fail(Boolean(wif1Run), "wif-1 GitHub run does not match approved workflow bytes and release marker");
  fail(cutoverPull && wif1Run && timestampBefore(cutoverPull.merged_at, wif1Run.started_at),
    "wif-1 run predates cutover pull request merge");
  fail(baselineRun && baselineRevision && wif1Run
    && timestampBefore(baselineRun.started_at, wif1Run.started_at)
    && timestampBefore(baselineRevision.data.create_time, wif1Run.started_at),
  "legacy baseline did not complete before wif-1");
  const wif1Revisions = entryOfKind(manifest.cutover.source_ids, "CLOUD_RUN_REVISION");
  fail(wif1Revisions.some(({ entry, data: revision }) => revision?.service === manifest.scope.allowed_service
    && revision?.revision === manifest.revisions.wif_1
    && revision?.release_marker === manifest.cutover.wif_1_release_marker
    && revision?.revision.endsWith(`-${revision.release_marker}`) && revisionScopeMatches(revision)
    && timestampBefore(wif1Run?.started_at, revision.create_time)
    && timestampBefore(revision.create_time, entry?.observed_at)),
  "wif-1 revision does not match its authoritative run window and release marker");

  const parity = entryOfKind(manifest.wif.source_ids, "GCP_WIF_PARITY");
  fail(parity.some(({ entry, data }) => data?.mode === manifest.wif.mode
    && data?.provider === manifest.wif.provider && data?.provider_config_hash === manifest.wif.config_hash
    && data?.parity_hash === manifest.wif.parity_hash
    && data?.owner_id === manifest.scope.owner_id && data?.repository_id === manifest.scope.repository_id
    && gcpScopeMatches(data) && data?.no_added_downstream_permissions === true
    && data?.region === manifest.scope.region
    && data?.allowed_service === manifest.scope.allowed_service
    && data?.forbidden_service === manifest.scope.forbidden_service
    && data?.no_forbidden_access === true && timestampAtOrBefore(data?.observed_after_at, entry?.observed_at)),
  "WIF parity artifact does not match exact scope and timeline");

  for (const hostile of manifest.hostile_tests) {
    const resultKind = hostile.id === "H8" ? "CLOUD_RUN_IAM_RESULT" : "STS_CLIENT_RESULT";
    const results = dataOfKind(hostile.source_ids, resultKind);
    const expectedCategory = hostile.id === "H7" ? "AUDIENCE_DENIED" : "WIF_CONDITION_DENIED";
    const runs = dataOfKind(hostile.source_ids, "GITHUB_RUN").filter(object);
    fail(results.some((result) => result?.hostile_id === hostile.id && result?.outcome === hostile.outcome
      && runs.some((run) => result?.run_id === run?.run_id && result?.run_attempt === run?.run_attempt
        && result?.head_sha === run?.head_sha)
      && (hostile.id === "H8" ? result?.target === manifest.scope.forbidden_service
        : result?.error_category === expectedCategory)), `${hostile.id} client artifact does not match its run`);
    const expectedWorkflowRef = `${manifest.scope.workflow_path}@refs/heads/main`;
    const contextMatches = runs.some((run) => {
      const exactRepository = run.owner_id === manifest.scope.owner_id && run.repository_id === manifest.scope.repository_id;
      const exactRef = run.ref === "refs/heads/main";
      const exactWorkflow = run.workflow_path === manifest.scope.workflow_path
        && run.workflow_ref?.endsWith(expectedWorkflowRef);
      const exactEvent = run.event === "push";
      const exactEnvironment = run.environment === "production";
      const exactH1Workflow = run.workflow_path === manifest.scope.h1_workflow_path
        && run.workflow_ref?.endsWith(`/${manifest.scope.h1_workflow_path}@refs/heads/main`);
      const exactH2Workflow = run.workflow_path === manifest.scope.h2_workflow_path
        && run.workflow_ref?.endsWith(`/${manifest.scope.h2_workflow_path}@refs/heads/main`);
      const cutoverBytes = run.workflow_blob_sha === manifest.cutover.workflow_blob_sha
        && run.workflow_sha256 === manifest.cutover.workflow_sha256;
      const h1Bytes = run.workflow_blob_sha === manifest.approved_workflows.h1.workflow_blob_sha
        && run.workflow_sha256 === manifest.approved_workflows.h1.workflow_sha256;
      const h2Bytes = run.workflow_blob_sha === manifest.approved_workflows.h2.workflow_blob_sha
        && run.workflow_sha256 === manifest.approved_workflows.h2.workflow_sha256;
      const h4Bytes = run.workflow_blob_sha === manifest.approved_workflows.h4.workflow_blob_sha
        && run.workflow_sha256 === manifest.approved_workflows.h4.workflow_sha256;
      if (hostile.id === "H1") return run.owner_id !== manifest.scope.owner_id
        && run.repository_id !== manifest.scope.repository_id && exactRef && exactH1Workflow
        && h1Bytes && exactEvent && exactEnvironment;
      if (hostile.id === "H2") return run.owner_id === manifest.scope.owner_id
        && run.repository_id !== manifest.scope.repository_id && exactRef && exactH2Workflow
        && h2Bytes && exactEvent && exactEnvironment;
      if (hostile.id === "H3") return exactRepository && !exactRef
        && run.workflow_path === manifest.scope.workflow_path && run.workflow_ref?.endsWith(`/${manifest.scope.workflow_path}@${run.ref}`)
        && cutoverBytes && exactEvent && exactEnvironment;
      if (hostile.id === "H4") return exactRepository && exactRef
        && run.workflow_path === manifest.scope.h4_workflow_path
        && run.workflow_ref?.endsWith(`/${manifest.scope.h4_workflow_path}@refs/heads/main`)
        && h4Bytes && exactEvent && exactEnvironment;
      if (hostile.id === "H5") return exactRepository && exactRef && exactWorkflow && cutoverBytes && !exactEvent && exactEnvironment;
      if (hostile.id === "H6") return exactRepository && exactRef && exactWorkflow && cutoverBytes && exactEvent && !exactEnvironment;
      return exactRepository && exactRef && exactWorkflow && cutoverBytes && exactEvent && exactEnvironment;
    });
    fail(contextMatches, `${hostile.id} GitHub identity case is not evidenced`);
    const expectedService = hostile.id === "H8" ? manifest.scope.forbidden_service : manifest.scope.allowed_service;
    const revisions = dataOfKind(hostile.source_ids, "CLOUD_RUN_REVISION");
    fail(revisions.some((data) => data?.service === expectedService
      && data?.revision === hostile.target_revision_before && data?.revision === hostile.target_revision_after
      && revisionScopeMatches(data)),
    `${hostile.id} unchanged target revision is not evidenced`);
  }
  const h8 = manifest.hostile_tests.find(({ id }) => id === "H8");
  const h8Run = entryOfKind(h8.source_ids, "GITHUB_RUN")[0];
  const h8Result = entryOfKind(h8.source_ids, "CLOUD_RUN_IAM_RESULT")[0];
  fail(object(h8Run?.data) && object(h8Result?.data)
    && timestampBefore(observedAt.get(forbiddenBeforeId), h8Run.data.started_at)
    && timestampAtOrBefore(h8Run.data.started_at, h8Result.data.denied_at)
    && timestampAtOrBefore(h8Result.data.denied_at, observedAt.get(forbiddenAfterHostileId)),
  "forbidden revision observations do not bracket H8");
}

async function snapshotArtifacts(evidence, readArtifact) {
  const snapshots = new Map();
  for (const entry of evidence) {
    if (snapshots.has(entry.id)) continue;
    try {
      const value = await readArtifact(entry.id);
      snapshots.set(entry.id, Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(value));
    } catch {
      // The integrity verifier emits the stable read error below.
    }
  }
  const integrity = await verifyEvidenceArtifacts({ evidence }, async (id) => {
    if (!snapshots.has(id)) throw new Error("missing evidence artifact");
    return snapshots.get(id);
  });
  return { integrity, snapshots };
}

function parsedArtifacts(evidence, snapshots, fail) {
  const artifacts = new Map();
  for (const entry of evidence) {
    const parsed = JSON.parse(snapshots.get(entry.id).toString("utf8"));
    artifacts.set(entry.id, parsed);
    validateArtifactData(entry.kind, parsed.data, fail, entry.id);
  }
  return artifacts;
}

function validateOccurrenceTimes(manifest, evidence, artifacts, fail) {
  const moments = [];
  for (const entry of evidence) {
    const data = artifacts.get(entry.id)?.data;
    const occurrences = occurrenceValues(manifest, entry, data).filter((value) => value !== undefined);
    for (const occurrence of occurrences) {
      fail(timestampAtOrBefore(occurrence, entry.observed_at), `${entry.id} occurrence is after its observation`);
      moments.push(occurrence);
    }
    if (entry.kind === "CLOUD_RUN_REVISION") {
      fail(timestampAtOrBefore(data?.create_time, entry.observed_at),
        `${entry.id} revision was created after its observation`);
    }
  }
  return moments;
}

function validateFinalCredentialScan(manifest, snapshots, artifacts, fail) {
  const scanEntries = manifest.evidence.filter(({ kind }) => kind === "LEAK_SCAN");
  const expectedId = manifest.leak_scan?.source_ids?.[0];
  fail(scanEntries.length === 1 && scanEntries[0]?.id === expectedId,
    "final credential scan source is missing or ambiguous");
  const scanEntry = scanEntries.length === 1 ? scanEntries[0] : null;
  if (!scanEntry) return;
  fail(scanEntry.locator === FINAL_SCAN_LOCATOR,
    "final credential scan locator is invalid");
  const scannedArtifacts = new Map();
  for (const entry of manifest.evidence) {
    if (entry.kind !== "LEAK_SCAN") scannedArtifacts.set(entry.id, snapshots.get(entry.id));
  }
  let expected;
  try {
    expected = createCredentialScan(manifest.scope, scannedArtifacts);
  } catch {
    fail(false, "final credential scan did not verify every non-scan artifact");
    return;
  }
  fail(canonicalJson(artifacts.get(scanEntry.id)?.data) === canonicalJson(expected),
    "final credential scan body does not match every non-scan artifact");
}

export async function verifyK0PreDisableEvidenceSemantics(fragment, evidence, readArtifact) {
  const structural = verifyK0PreDisableFragment(fragment, evidence);
  if (!structural.ok) return structural;
  const { integrity, snapshots } = await snapshotArtifacts(evidence, readArtifact);
  if (!integrity.ok) return integrity;

  const errors = [];
  const fail = (condition, message) => { if (!condition) errors.push(message); };
  const entries = new Map(evidence.map((entry) => [entry.id, entry]));
  const artifacts = parsedArtifacts(evidence, snapshots, fail);
  validateOccurrenceTimes(fragment, evidence, artifacts, fail);
  const observedAt = new Map(evidence.map((entry) => [entry.id, entry.observed_at]));
  validatePreDisableSemantics(fragment, entries, artifacts, observedAt, fail);
  return { ok: errors.length === 0, errors };
}

export async function verifyK0EvidenceSemantics(manifest, readArtifact) {
  const { integrity, snapshots } = await snapshotArtifacts(manifest.evidence, readArtifact);
  if (!integrity.ok) return integrity;

  const errors = [];
  const fail = (condition, message) => { if (!condition) errors.push(message); };
  const entries = new Map(manifest.evidence.map((entry) => [entry.id, entry]));
  const artifacts = parsedArtifacts(manifest.evidence, snapshots, fail);
  validateFinalCredentialScan(manifest, snapshots, artifacts, fail);
  const dataOfKind = (ids, kind) => ids
    .filter((id) => entries.get(id)?.kind === kind)
    .map((id) => artifacts.get(id)?.data);
  const entryOfKind = (ids, kind) => ids
    .filter((id) => entries.get(id)?.kind === kind)
    .map((id) => ({ entry: entries.get(id), data: artifacts.get(id)?.data }));
  const gcpScopeMatches = (data) => data?.project_id === manifest.scope.project_id
    && data?.project_number === manifest.scope.project_number
    && data?.service_account_email === manifest.scope.service_account_email
    && data?.service_account_unique_id === manifest.scope.service_account_unique_id;
  const revisionScopeMatches = (data) => data?.project_id === manifest.scope.project_id
    && data?.region === manifest.scope.region;
  const runMatches = (run, claim, workflowPath = manifest.scope.workflow_path) => run?.run_id === claim.run_id
    && run?.run_attempt === claim.run_attempt && run?.head_sha === claim.head_sha
    && run?.owner_id === manifest.scope.owner_id && run?.repository_id === manifest.scope.repository_id
    && run?.workflow_path === workflowPath
    && run?.workflow_ref?.endsWith(`/${workflowPath}@refs/heads/main`)
    && run?.ref === "refs/heads/main" && run?.environment === "production"
    && run?.runner_environment === "github-hosted" && run?.conclusion === "success";
  const reviewMatches = (review, run) => review?.run_id === run?.run_id
    && review?.run_attempt === run?.run_attempt && review?.head_sha === run?.head_sha
    && review?.environment === run?.environment && review?.actor_id === run?.actor_id
    && review?.reviewer_id !== run?.actor_id && review?.state === "approved";

  const fragment = preDisableFragment(manifest);
  const preDisableIds = preDisableSourceIds(fragment);
  const checkpointId = manifest.checkpoint?.source_id;
  const checkpointEntry = entries.get(checkpointId);
  const checkpoint = artifacts.get(checkpointId)?.data;
  let checkpointReceipt;
  try {
    checkpointReceipt = parseGitHubEvidenceCheckpointReceipt(
      Buffer.from(checkpoint?.receipt?.bytes_base64 ?? "", "base64"),
    ).receipt;
  } catch {
    checkpointReceipt = null;
  }
  fail(checkpointEntry?.kind === "GITHUB_EVIDENCE_CHECKPOINT"
    && checkpoint?.owner_id === manifest.scope.owner_id && checkpoint?.repository_id === manifest.scope.repository_id,
  "evidence checkpoint does not match repository scope");
  fail(checkpointEntry?.observed_at === checkpoint?.collected_at,
    "evidence checkpoint observation is not its authenticated collection time");
  fail(timestampBefore(checkpoint?.check?.completed_at, manifest.disable.audit_timestamp)
    && timestampBefore(checkpoint?.run?.completed_at, manifest.disable.audit_timestamp),
  "evidence checkpoint did not complete before key disable");

  const records = new Map(checkpointReceipt?.evidence?.map((record) => [record.id, record]) ?? []);
  fail(records.size === preDisableIds.size && [...records.keys()].every((id) => preDisableIds.has(id)),
    "evidence checkpoint does not exactly cover pre-disable evidence");
  const moments = [
    manifest.assembled_at,
    manifest.disable.audit_timestamp,
    checkpoint?.pull?.reviewed_at,
    checkpoint?.pull?.merged_at,
    checkpoint?.run?.started_at,
    checkpoint?.run?.completed_at,
    checkpoint?.check?.started_at,
    checkpoint?.check?.completed_at,
    ...validateOccurrenceTimes(manifest, manifest.evidence, artifacts, fail),
  ];
  for (const entry of manifest.evidence) {
    fail(timestampAtOrBefore(entry.observed_at, manifest.assembled_at), `${entry.id} was observed after assembly`);
  }
  for (const id of preDisableIds) {
    const entry = entries.get(id);
    const data = artifacts.get(id)?.data;
    const record = records.get(id);
    const digest = data === undefined ? null : createHash("sha256").update(canonicalJson(data)).digest("hex");
    fail(record?.kind === entry?.kind && record?.locator === entry?.locator && record?.data_sha256 === digest,
      `${id} pre-disable fact is not bound to the reviewed checkpoint`);
    fail(timestampAtOrBefore(record?.recorded_at, checkpoint?.pull?.reviewed_at)
      && timestampAtOrBefore(record?.recorded_at, entry?.observed_at)
      && timestampBefore(record?.recorded_at, manifest.disable.audit_timestamp),
    `${id} reviewed checkpoint occurrence is late`);
    for (const occurrence of occurrenceValues(manifest, entry, data).filter((value) => value !== undefined)) {
      fail(timestampAtOrBefore(occurrence, record?.recorded_at)
        && timestampBefore(occurrence, manifest.disable.audit_timestamp), `${id} pre-disable event is late`);
    }
    moments.push(record?.recorded_at);
  }
  validatePreDisableSemantics(
    fragment,
    entries,
    artifacts,
    new Map([...records].map(([id, record]) => [id, record.recorded_at])),
    fail,
  );

  const assembled = timestampNanoseconds(manifest.assembled_at);
  const earliest = moments.map(timestampNanoseconds).filter((value) => value !== null)
    .reduce((left, right) => left < right ? left : right, assembled);
  fail(assembled !== null && earliest !== null && assembled >= earliest
    && assembled - earliest <= 48n * 60n * 60n * 1_000_000_000n, "K0 transaction exceeds 48 hours");

  const forbiddenAfterId = manifest.revisions.forbidden_after_source_id;
  const forbiddenAfter = artifacts.get(forbiddenAfterId)?.data;
  fail(forbiddenAfter?.service === manifest.scope.forbidden_service
    && forbiddenAfter?.revision === manifest.revisions.forbidden_after && revisionScopeMatches(forbiddenAfter),
  "forbidden-after revision artifact does not match");
  fail(timestampBefore(records.get(manifest.revisions.forbidden_after_hostile_source_id)?.recorded_at,
    entries.get(forbiddenAfterId)?.observed_at), "forbidden revision observations are stale or out of order");
  const disabledKeys = entryOfKind(manifest.disable.source_ids, "GCP_IAM_KEY");
  fail(disabledKeys.some(({ entry, data }) => data?.key_id === manifest.scope.key_id && data?.disabled === true
    && gcpScopeMatches(data) && timestampBefore(manifest.disable.audit_timestamp, entry?.observed_at)),
  "disabled-key artifact does not match scope or timeline");
  const disableAudits = entryOfKind(manifest.disable.source_ids, "GCP_AUDIT_ENTRY");
  fail(disableAudits.some(({ entry, data }) => data?.principal_email === manifest.disable.human_actor
    && data?.key_id === manifest.scope.key_id && data?.service_account_unique_id === manifest.scope.service_account_unique_id
    && data?.insert_id === manifest.disable.audit_insert_id && data?.timestamp === manifest.disable.audit_timestamp
    && data?.method_name === "google.iam.admin.v1.DisableServiceAccountKey" && data?.status === "SUCCEEDED"
    && gcpScopeMatches(data) && timestampAtOrBefore(data.timestamp, entry?.observed_at)), "human disable audit artifact does not match scope or timeline");

  const legacyRuns = dataOfKind(manifest.legacy_after_disable.source_ids, "GITHUB_RUN");
  const legacyResults = dataOfKind(manifest.legacy_after_disable.source_ids, "GOOGLE_AUTH_RESULT");
  const legacyRun = legacyRuns.find((run) => runMatches(run, manifest.legacy_after_disable, manifest.scope.legacy_workflow_path)
    && run?.event === "workflow_dispatch"
    && run?.workflow_blob_sha === manifest.approved_workflows.legacy.workflow_blob_sha
    && run?.workflow_sha256 === manifest.approved_workflows.legacy.workflow_sha256
    && timestampBefore(manifest.disable.audit_timestamp, run?.started_at));
  fail(Boolean(legacyRun),
  "fresh legacy GitHub run does not match or predates key disable");
  const legacyResult = legacyResults.find((result) => result?.key_id === manifest.scope.key_id
    && result?.run_id === manifest.legacy_after_disable.run_id
    && result?.run_attempt === manifest.legacy_after_disable.run_attempt
    && result?.head_sha === manifest.legacy_after_disable.head_sha
    && result?.owner_id === manifest.scope.owner_id && result?.repository_id === manifest.scope.repository_id
    && result?.workflow_path === manifest.scope.legacy_workflow_path
    && result?.workflow_ref?.endsWith(`/${manifest.scope.legacy_workflow_path}@refs/heads/main`)
    && result?.ref === "refs/heads/main" && result?.reached_google === true
    && result?.rejection_category === "DISABLED_OR_INVALID_KEY"
    && timestampBefore(manifest.disable.audit_timestamp, result?.rejected_at));
  fail(Boolean(legacyResult) && timestampAtOrBefore(legacyRun?.started_at, legacyResult.rejected_at),
    "fresh legacy-auth artifact does not match scope or timeline");

  const postRuns = dataOfKind(manifest.post_disable.source_ids, "GITHUB_RUN");
  const postReviews = dataOfKind(manifest.post_disable.source_ids, "GITHUB_ENVIRONMENT_REVIEW");
  const postRun = postRuns.find((run) => runMatches(run, manifest.post_disable) && run?.event === "push"
    && run?.workflow_blob_sha === manifest.cutover.workflow_blob_sha
    && run?.workflow_sha256 === manifest.cutover.workflow_sha256
    && run?.release_marker === manifest.post_disable.release_marker
    && timestampBefore(manifest.disable.audit_timestamp, run?.started_at)
    && postReviews.some((review) => reviewMatches(review, run)));
  fail(Boolean(postRun), "post-disable WIF GitHub run does not match or predates key disable");
  fail(Boolean(legacyResult) && Boolean(postRun)
    && timestampBefore(legacyResult.rejected_at, postRun.started_at),
  "fresh legacy denial must strictly precede post-disable WIF run");
  const wifAudits = entryOfKind(manifest.post_disable.source_ids, "GCP_WIF_AUDIT_LOG");
  const matchedWifAudit = wifAudits.map(({ entry, data }) => {
    try {
      return { entry, claims: parseWifAuditEvidence(Buffer.from(canonicalJson(data))) };
    } catch {
      return null;
    }
  }).filter(Boolean).find(({ claims }) => claims.provider === manifest.wif.provider
    && claims?.audience === `https://iam.googleapis.com/${manifest.wif.provider}`
    && claims?.idp_subject === manifest.wif.idp_subject
    && claims?.mapped_principal === manifest.wif.mapped_principal
    && claims?.project_id === manifest.scope.project_id && claims?.project_number === manifest.scope.project_number
    && claims?.service_account_email === manifest.scope.service_account_email
    && claims?.service_account_unique_id === manifest.scope.service_account_unique_id
    && timestampBefore(manifest.disable.audit_timestamp, claims?.exchanged_at));
  fail(matchedWifAudit && timestampAtOrBefore(postRun?.started_at, matchedWifAudit.claims.exchanged_at)
    && timestampAtOrBefore(matchedWifAudit.claims.authenticated_at, matchedWifAudit.entry.observed_at),
    "post-disable WIF audit does not match scope or timeline");
  const postRevisions = entryOfKind(manifest.post_disable.source_ids, "CLOUD_RUN_REVISION");
  const matchedPostRevision = postRevisions.find(({ data }) => data?.service === manifest.scope.allowed_service
    && data?.revision === manifest.revisions.wif_2 && data?.release_marker === manifest.post_disable.release_marker
    && data?.revision.endsWith(`-${data.release_marker}`) && revisionScopeMatches(data));
  fail(Boolean(matchedPostRevision) && timestampBefore(postRun?.started_at, matchedPostRevision.data.create_time)
    && timestampBefore(matchedPostRevision.data.create_time, matchedPostRevision.entry.observed_at),
  "post-disable Cloud Run revision does not match its authoritative run window and release marker");
  fail(matchedPostRevision && matchedWifAudit
    && timestampBefore(manifest.disable.audit_timestamp, matchedPostRevision.data.create_time)
    && timestampAtOrBefore(matchedWifAudit.claims.authenticated_at, matchedPostRevision.data.create_time)
    && timestampBefore(records.get(manifest.revisions.forbidden_after_hostile_source_id)?.recorded_at, postRun?.started_at)
    && timestampBefore(matchedPostRevision.data.create_time, entries.get(forbiddenAfterId)?.observed_at),
  "forbidden revision observations do not bracket wif-2");
  return { ok: errors.length === 0, errors };
}
