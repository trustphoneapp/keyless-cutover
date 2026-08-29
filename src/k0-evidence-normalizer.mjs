import { createHash } from "node:crypto";

import { canonicalJson } from "./evidence-artifact.mjs";
import { isRfc3339, timestampNanoseconds } from "./rfc3339.mjs";

const SHA1 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const NUMERIC = /^\d+$/;
const PROVIDER = /^projects\/\d+\/locations\/global\/workloadIdentityPools\/[a-z0-9-]+\/providers\/[a-z0-9-]+$/;
const SERVICE_ACCOUNT = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;
const RUN_FIELDS = new Set([
  "run_id", "run_attempt", "head_sha", "workflow_path", "workflow_ref", "workflow_blob_sha", "workflow_sha256",
  "owner_id", "repository_id", "actor_id", "event", "ref", "environment", "conclusion", "runner_environment", "started_at",
  "release_marker",
]);
const REVISION_FIELDS = new Set([
  "project_id", "region", "service", "revision", "create_time", "release_marker", "image_digest",
]);
const RESPONSE_FIELDS = new Set(["entries"]);
const ENTRY_FIELDS = new Set(["insertId", "timestamp", "protoPayload", "resource"]);
const STS_REQUIRED = new Set(["@type", "authenticationInfo", "metadata", "methodName", "request", "resourceName"]);
const IAM_REQUIRED = new Set(["@type", "authenticationInfo", "methodName", "request", "resourceName"]);
const OPTIONAL_AUDIT_FIELDS = new Set(["serviceName", "status"]);
const PRINCIPAL_REQUIRED = new Set(["principalSubject"]);
const OPTIONAL_PRINCIPAL_FIELDS = new Set(["principalEmail"]);
// Cloud Audit Logs attribute a federated-token-authenticated GenerateAccessToken to the impersonated
// service account: the IAM entry carries principalEmail and never principalSubject, unlike the STS
// entry. Observed on every federated GenerateAccessToken this project has produced; see
// docs/evidence/forensics/all-wif-audit-entries.json. The email is bound to the expected deploy
// service account below, so the relaxed shape is paid for with a stricter value binding.
const IAM_PRINCIPAL_REQUIRED = new Set(["principalEmail"]);
const OPTIONAL_IAM_PRINCIPAL_FIELDS = new Set(["principalSubject"]);
// Google logs the full STS API parameter set, not the two fields its published examples show. Each
// value is pinned below rather than merely permitted.
const STS_REQUEST_REQUIRED = new Set([
  "@type", "audience", "grantType", "requestedTokenType", "subjectTokenType",
]);
const STS_AUDIT_DATA_TYPE = "type.googleapis.com/google.identity.sts.v1.AuditData";
const STS_SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
const STS_REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const IAM_REQUEST_REQUIRED = new Set(["@type", "name"]);
const OPTIONAL_IAM_REQUEST_FIELDS = new Set(["lifetime", "scope"]);
const CHECKPOINT_RECEIPT_FIELDS = new Set(["version", "evidence"]);
const CHECKPOINT_RECORD_FIELDS = new Set(["id", "kind", "locator", "recorded_at", "data_sha256"]);

function exactObject(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === fields.size && Object.keys(value).every((key) => fields.has(key));
}

function boundedObject(value, required, optional) {
  return value && typeof value === "object" && !Array.isArray(value)
    && [...required].every((key) => Object.hasOwn(value, key))
    && Object.keys(value).every((key) => required.has(key) || optional.has(key));
}

function exactAuditFields(value, required) {
  return boundedObject(value, required, OPTIONAL_AUDIT_FIELDS);
}

function boundedText(value) {
  return typeof value === "string" && Boolean(value) && value.length <= 2048 && !/[\r\n]/.test(value);
}

function validRun(run) {
  return exactObject(run, RUN_FIELDS) && NUMERIC.test(run.run_id) && NUMERIC.test(run.run_attempt)
    && SHA1.test(run.head_sha) && SHA1.test(run.workflow_blob_sha) && SHA256.test(run.workflow_sha256)
    && NUMERIC.test(run.owner_id) && NUMERIC.test(run.repository_id) && NUMERIC.test(run.actor_id)
    && run.ref === "refs/heads/main" && run.environment === "production" && run.conclusion === "success"
    && run.runner_environment === "github-hosted" && isRfc3339(run.started_at)
    && (run.release_marker === null || /^[a-z0-9][a-z0-9-]{0,19}$/.test(run.release_marker));
}

export function normalizeProofV2Evidence({ observation, receipt }) {
  if (!observation || !receipt || !SHA1.test(observation.workflow_blob_sha ?? "")
      || !SHA256.test(observation.workflow_sha256 ?? "") || !isRfc3339(observation.started_at)
      || observation.event_name !== "workflow_dispatch" || observation.ref !== "refs/heads/main"
      || observation.environment !== "production" || observation.runner_environment !== "github-hosted"
      || receipt.run_id !== observation.run_id || !SHA256.test(receipt.proof_digest ?? "")
      || !SHA1.test(receipt.key_id ?? "")) {
    throw new Error("ProofV2 collector output is invalid");
  }
  const githubRun = {
    run_id: observation.run_id,
    run_attempt: observation.run_attempt,
    head_sha: observation.head_sha,
    workflow_path: observation.workflow_path,
    workflow_ref: observation.workflow_ref,
    workflow_blob_sha: observation.workflow_blob_sha,
    workflow_sha256: observation.workflow_sha256,
    owner_id: observation.owner_id,
    repository_id: observation.repository_id,
    actor_id: observation.actor_id,
    event: observation.event_name,
    ref: observation.ref,
    environment: observation.environment,
    conclusion: "success",
    runner_environment: observation.runner_environment,
    started_at: observation.started_at,
    release_marker: null,
  };
  if (!validRun(githubRun) || observation.environment_review?.state !== "approved"
      || observation.environment_review.environment !== observation.environment
      || observation.environment_review.reviewer_id === observation.actor_id) {
    throw new Error("ProofV2 run or independent review is invalid");
  }
  return {
    githubRun,
    environmentReview: {
      run_id: observation.run_id,
      run_attempt: observation.run_attempt,
      head_sha: observation.head_sha,
      environment: observation.environment,
      actor_id: observation.actor_id,
      reviewer_id: observation.environment_review.reviewer_id,
      state: "approved",
    },
    proofArtifact: {
      challenge_id: receipt.challenge_id,
      proof_digest: receipt.proof_digest,
      key_id: receipt.key_id,
      run_id: observation.run_id,
      run_attempt: observation.run_attempt,
      head_sha: observation.head_sha,
      verified: receipt.verified === true,
      consumed: receipt.consumed === true,
    },
  };
}

export function parseWifAuditEvidence(auditLog) {
  if (!Buffer.isBuffer(auditLog) || !auditLog.length || auditLog.length > 1_000_000) {
    throw new Error("WIF audit evidence is invalid");
  }
  let parsed;
  try {
    parsed = JSON.parse(auditLog.toString("utf8"));
  } catch {
    throw new Error("WIF audit evidence is not JSON");
  }
  if (auditLog.toString("utf8") !== canonicalJson(parsed) || !exactObject(parsed, RESPONSE_FIELDS)
      || !Array.isArray(parsed.entries) || parsed.entries.length !== 2
      || parsed.entries.some((entry) => !exactObject(entry, ENTRY_FIELDS) || !isRfc3339(entry.timestamp))) {
    throw new Error("WIF audit evidence shape is invalid");
  }
  const sts = parsed.entries.filter(({ protoPayload }) => protoPayload?.methodName
    === "google.identity.sts.v1.SecurityTokenService.ExchangeToken");
  const iamMethods = new Set(["GenerateAccessToken", "google.iam.credentials.v1.IAMCredentials.GenerateAccessToken"]);
  const iam = parsed.entries.filter(({ protoPayload }) => iamMethods.has(protoPayload?.methodName));
  if (sts.length !== 1 || iam.length !== 1 || !exactAuditFields(sts[0].protoPayload, STS_REQUIRED)
      || !exactAuditFields(iam[0].protoPayload, IAM_REQUIRED)) {
    throw new Error("WIF audit methods are missing or ambiguous");
  }
  const stsPayload = sts[0].protoPayload;
  const iamPayload = iam[0].protoPayload;
  const idpSubject = stsPayload.authenticationInfo?.principalSubject;
  const mappedPrincipal = stsPayload.metadata?.mapped_principal;
  const provider = stsPayload.resourceName;
  const principalPrefix = typeof provider === "string"
    ? `principal://iam.googleapis.com/${provider.replace(/\/providers\/[a-z0-9-]+$/, "")}/subject/`
    : "";
  const serviceAccountEmail = iamPayload.request?.name?.match(/^projects\/-\/serviceAccounts\/(.+)$/)?.[1];
  const stsLabels = sts[0].resource?.labels;
  const labels = iam[0].resource?.labels;
  if (stsPayload["@type"] !== "type.googleapis.com/google.cloud.audit.AuditLog"
      || (stsPayload.serviceName !== undefined && stsPayload.serviceName !== "sts.googleapis.com")
      || !PROVIDER.test(provider ?? "")
      || !boundedObject(stsPayload.authenticationInfo, PRINCIPAL_REQUIRED, OPTIONAL_PRINCIPAL_FIELDS)
      || (stsPayload.authenticationInfo.principalEmail !== undefined
        && !boundedText(stsPayload.authenticationInfo.principalEmail))
      || !exactObject(stsPayload.metadata, new Set(["@type", "mapped_principal"]))
      || stsPayload.metadata["@type"] !== STS_AUDIT_DATA_TYPE
      || !exactObject(stsPayload.request, STS_REQUEST_REQUIRED)
      || stsPayload.request["@type"] !== "type.googleapis.com/google.identity.sts.v1.ExchangeTokenRequest"
      || stsPayload.request.grantType !== "urn:ietf:params:oauth:grant-type:token-exchange"
      || stsPayload.request.subjectTokenType !== STS_SUBJECT_TOKEN_TYPE
      || stsPayload.request.requestedTokenType !== STS_REQUESTED_TOKEN_TYPE
      || stsPayload.request.audience !== `//iam.googleapis.com/${provider}`
      || (stsPayload.status !== undefined && !exactObject(stsPayload.status, new Set()))
      || typeof idpSubject !== "string" || !idpSubject || typeof mappedPrincipal !== "string"
      || !mappedPrincipal.startsWith(principalPrefix) || mappedPrincipal.length === principalPrefix.length
      || !exactObject(sts[0].resource, new Set(["type", "labels"])) || sts[0].resource.type !== "audited_resource"
      || !exactObject(stsLabels, new Set(["method", "project_id", "service"]))
      || stsLabels.method !== stsPayload.methodName || stsLabels.service !== "sts.googleapis.com"
      || iamPayload["@type"] !== "type.googleapis.com/google.cloud.audit.AuditLog"
      || (iamPayload.serviceName !== undefined && iamPayload.serviceName !== "iamcredentials.googleapis.com")
      || !boundedObject(iamPayload.authenticationInfo, IAM_PRINCIPAL_REQUIRED, OPTIONAL_IAM_PRINCIPAL_FIELDS)
      || !boundedText(iamPayload.authenticationInfo.principalEmail)
      || iamPayload.authenticationInfo.principalEmail !== serviceAccountEmail
      || (iamPayload.authenticationInfo.principalSubject !== undefined
        && iamPayload.authenticationInfo.principalSubject !== mappedPrincipal)
      || !boundedObject(iamPayload.request, IAM_REQUEST_REQUIRED, OPTIONAL_IAM_REQUEST_FIELDS)
      || (iamPayload.request.lifetime !== undefined && !boundedText(iamPayload.request.lifetime))
      || (iamPayload.request.scope !== undefined && (!Array.isArray(iamPayload.request.scope)
        || !iamPayload.request.scope.length || iamPayload.request.scope.length > 20
        || !iamPayload.request.scope.every(boundedText)))
      || iamPayload.request["@type"] !== "type.googleapis.com/google.iam.credentials.v1.GenerateAccessTokenRequest"
      || !SERVICE_ACCOUNT.test(serviceAccountEmail ?? "")
      || ![iamPayload.request.name, `projects/-/serviceAccounts/${labels?.unique_id}`].includes(iamPayload.resourceName)
      || (iamPayload.status !== undefined && !exactObject(iamPayload.status, new Set()))
      || iam[0].resource?.type !== "service_account"
      || !exactObject(iam[0].resource, new Set(["type", "labels"]))
      || !exactObject(labels, new Set(["email_id", "project_id", "unique_id"]))
      || labels.email_id !== serviceAccountEmail || !NUMERIC.test(labels.unique_id ?? "")
      || typeof labels.project_id !== "string" || !labels.project_id || stsLabels.project_id !== labels.project_id
      || !NUMERIC.test(provider.split("/")[1] ?? "") || typeof sts[0].insertId !== "string"
      || typeof iam[0].insertId !== "string" || !sts[0].insertId || !iam[0].insertId
      || sts[0].insertId === iam[0].insertId) {
    throw new Error("WIF audit identity is invalid");
  }
  const exchangedAt = timestampNanoseconds(sts[0].timestamp);
  const authenticatedAt = iam[0].timestamp;
  const authenticated = timestampNanoseconds(authenticatedAt);
  if (authenticated < exchangedAt || authenticated - exchangedAt > 10n * 60n * 1_000_000_000n) {
    throw new Error("WIF audit timeline is invalid");
  }
  return {
    provider,
    audience: `https://iam.googleapis.com/${provider}`,
    idp_subject: idpSubject,
    mapped_principal: mappedPrincipal,
    project_id: labels.project_id,
    project_number: provider.split("/")[1],
    service_account_email: serviceAccountEmail,
    service_account_unique_id: labels.unique_id,
    sts_insert_id: sts[0].insertId,
    iam_insert_id: iam[0].insertId,
    exchanged_at: sts[0].timestamp,
    authenticated_at: authenticatedAt,
  };
}

export function parseGitHubEvidenceCheckpointReceipt(receiptBytes) {
  if (!Buffer.isBuffer(receiptBytes) || !receiptBytes.length || receiptBytes.length > 64 * 1024) {
    throw new Error("GitHub evidence checkpoint receipt is invalid");
  }
  let parsed;
  try {
    parsed = JSON.parse(receiptBytes.toString("utf8"));
  } catch {
    throw new Error("GitHub evidence checkpoint receipt is not JSON");
  }
  if (receiptBytes.toString("utf8") !== canonicalJson(parsed)
      || !exactObject(parsed, CHECKPOINT_RECEIPT_FIELDS) || parsed.version !== 1
      || !Array.isArray(parsed.evidence) || !parsed.evidence.length || parsed.evidence.length > 100
      || parsed.evidence.some((record) => !exactObject(record, CHECKPOINT_RECORD_FIELDS)
        || !/^E[0-9]{3}$/.test(record.id) || typeof record.kind !== "string" || !record.kind
        || typeof record.locator !== "string" || !record.locator || /[\r\n]/.test(record.locator)
        || !isRfc3339(record.recorded_at) || !SHA256.test(record.data_sha256))) {
    throw new Error("GitHub evidence checkpoint receipt shape is invalid");
  }
  const ids = parsed.evidence.map(({ id }) => id);
  if (new Set(ids).size !== ids.length || ids.some((id, index) => index > 0 && ids[index - 1] >= id)) {
    throw new Error("GitHub evidence checkpoint receipt order is invalid");
  }
  const gitHeader = Buffer.from(`blob ${receiptBytes.length}\0`);
  return {
    receipt: parsed,
    receipt_sha256: createHash("sha256").update(receiptBytes).digest("hex"),
    receipt_blob_sha: createHash("sha1").update(gitHeader).update(receiptBytes).digest("hex"),
    receipt_bytes_base64: receiptBytes.toString("base64"),
  };
}

export function normalizeCloudRunObservation(value) {
  if (!exactObject(value, REVISION_FIELDS) || !isRfc3339(value.create_time)
      || !/^[a-z0-9][a-z0-9-]{0,19}$/.test(value.release_marker)
      || !/^sha256:[a-f0-9]{64}$/.test(value.image_digest)) {
    throw new Error("Cloud Run collector output is invalid");
  }
  return structuredClone(value);
}

export function normalizeGoogleKeyEvidence({ key, scope }) {
  const keyId = key?.name?.split("/").at(-1);
  if (!SHA1.test(keyId ?? "") || !scope || key?.keyType !== "USER_MANAGED"
      || key?.keyAlgorithm !== "KEY_ALG_RSA_2048" || typeof key.disabled !== "boolean") {
    throw new Error("Google key collector output is invalid");
  }
  return {
    name: key.name,
    key_id: keyId,
    key_type: key.keyType,
    algorithm: key.keyAlgorithm,
    disabled: key.disabled,
    project_id: scope.project_id,
    project_number: scope.project_number,
    service_account_email: scope.service_account_email,
    service_account_unique_id: scope.service_account_unique_id,
  };
}
