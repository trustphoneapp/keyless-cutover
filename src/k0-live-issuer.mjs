import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";

import { assertCredentialFreeBytes, createCredentialScan } from "./credential-scan.mjs";
import { canonicalJson, createEvidenceArtifact, decodeUtf8 } from "./evidence-artifact.mjs";
import { createGcpEvidenceReader } from "./gcp-evidence.mjs";
import { collectFreshLegacyDenialEvidence } from "./github-legacy-evidence.mjs";
import { collectGitHubEvidenceCheckpoint, collectGitHubSuccessfulDeploy } from "./github-positive-evidence.mjs";
import { requireGitHubReadToken } from "./github-token.mjs";
import { createGoogleKeyReaderObserved } from "./google-key-reader.mjs";
import { verifyK0Bundle } from "./k0-bundle.mjs";
import { normalizeGoogleKeyEvidence } from "./k0-evidence-normalizer.mjs";
import { createKmsSigningRequest } from "./k0-kms.mjs";
import { expandK0PreDisableArchive } from "./k0-predisable-archive.mjs";
import { createK0Receipt, verifyK0Receipt } from "./k0-receipt.mjs";
import { timestampNanoseconds } from "./rfc3339.mjs";
import { rejectDuplicateJsonKeys } from "./observation-time.mjs";

const DOMAIN = "KEYLESS_K0_LIVE_RECOLLECTION_PLAN_V1";
const MAX_PLAN = 32 * 1024;
const PLAN_FIELDS = new Set(["version", "domain", "github", "gcp", "kms"]);
const GITHUB_FIELDS = new Set([
  "owner", "repository", "checkpoint_pull_number", "receipt_path", "archive_path", "legacy_run_id", "wif2_run_id",
]);
const GCP_FIELDS = new Set(["disable_actor"]);
const KMS_FIELDS = new Set(["key_version"]);
const CREDENTIAL_FIELDS = new Set(["installationToken", "googleAuth"]);
const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}$/;
const NUMERIC = /^\d+$/;
const HUMAN_ACTOR = /^(?=.{3,254}$)(?=[^@]{1,64}@)[a-z0-9](?:[a-z0-9_+-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_+-]*[a-z0-9])?)*@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const KEY_VERSION = /^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/locations\/[A-Za-z0-9_-]{1,63}\/keyRings\/[A-Za-z0-9_-]{1,63}\/cryptoKeys\/[A-Za-z0-9_-]{1,63}\/cryptoKeyVersions\/[1-9]\d*$/;

function exactObject(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === fields.size
    && Object.keys(value).every((key) => fields.has(key));
}

function exact(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function evidencePath(value, name) {
  const segments = typeof value === "string" ? value.split("/") : [];
  if (typeof value !== "string" || value.length > 256 || segments[0] !== "docs" || segments[1] !== "evidence"
      || segments.length < 3 || segments.some((segment) => !/^[A-Za-z0-9._-]+$/.test(segment)
        || segment === "." || segment === "..")
      || !/^[A-Za-z0-9._-]+\.json$/.test(segments.at(-1))) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

export function parseK0LiveRecollectionPlan(planBytes) {
  if (!Buffer.isBuffer(planBytes) || !planBytes.length || planBytes.length > MAX_PLAN) {
    throw new Error("K0 live recollection plan bytes are invalid");
  }
  const captured = Buffer.from(planBytes);
  assertCredentialFreeBytes(captured);
  let plan;
  try {
    const text = decodeUtf8(captured);
    rejectDuplicateJsonKeys(text);
    plan = JSON.parse(text);
  } catch (error) {
    if (error?.message === "duplicate JSON key") {
      throw new Error("K0 live recollection plan contains duplicate JSON keys");
    }
    throw new Error("K0 live recollection plan is not JSON");
  }
  if (!captured.equals(Buffer.from(canonicalJson(plan), "utf8")) || !exactObject(plan, PLAN_FIELDS)
      || plan.version !== 1 || plan.domain !== DOMAIN || !exactObject(plan.github, GITHUB_FIELDS)
      || !exactObject(plan.gcp, GCP_FIELDS) || !exactObject(plan.kms, KMS_FIELDS)) {
    throw new Error("K0 live recollection plan is invalid");
  }
  exact(plan.github.owner, OWNER, "GitHub owner");
  exact(plan.github.repository, REPOSITORY, "GitHub repository");
  if (!Number.isInteger(plan.github.checkpoint_pull_number) || plan.github.checkpoint_pull_number < 1) {
    throw new Error("checkpoint pull number is invalid");
  }
  exact(plan.github.legacy_run_id, NUMERIC, "legacy run ID");
  exact(plan.github.wif2_run_id, NUMERIC, "wif-2 run ID");
  if (plan.github.legacy_run_id === plan.github.wif2_run_id) {
    throw new Error("legacy and wif-2 run IDs must be distinct");
  }
  evidencePath(plan.github.receipt_path, "checkpoint receipt path");
  evidencePath(plan.github.archive_path, "checkpoint archive path");
  if (plan.github.receipt_path === plan.github.archive_path) throw new Error("checkpoint evidence paths must differ");
  exact(plan.gcp.disable_actor, HUMAN_ACTOR, "disable actor");
  exact(plan.kms.key_version, KEY_VERSION, "KMS key version");
  return plan;
}

function capturedCredentials(credentials) {
  if (!credentials || typeof credentials !== "object" || utilTypes.isProxy(credentials)
      || !exactObject(credentials, CREDENTIAL_FIELDS)) {
    throw new Error("K0 live recollection credentials are invalid");
  }
  const descriptors = Object.getOwnPropertyDescriptors(credentials);
  if (Object.values(descriptors).some((descriptor) => !("value" in descriptor) || descriptor.enumerable !== true)) {
    throw new Error("K0 live recollection credentials are invalid");
  }
  const installationToken = requireGitHubReadToken(descriptors.installationToken.value);
  const googleAuth = descriptors.googleAuth.value;
  if (!googleAuth || typeof googleAuth !== "object" || utilTypes.isProxy(googleAuth)) {
    throw new Error("K0 live recollection Google authentication is invalid");
  }
  let method;
  let current = googleAuth;
  for (let depth = 0; current && depth < 8 && method === undefined; depth += 1) {
    if (utilTypes.isProxy(current)) throw new Error("K0 live recollection Google authentication is invalid");
    let descriptor;
    try { descriptor = Object.getOwnPropertyDescriptor(current, "getClient"); } catch {
      throw new Error("K0 live recollection Google authentication is invalid");
    }
    if (descriptor) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") {
        throw new Error("K0 live recollection Google authentication is invalid");
      }
      method = descriptor.value;
      break;
    }
    current = Object.getPrototypeOf(current);
  }
  if (!method) throw new Error("K0 live recollection Google authentication is invalid");
  return {
    installationToken,
    googleAuth: Object.freeze({ getClient: (...args) => Reflect.apply(method, googleAuth, args) }),
  };
}

function latestTime(values) {
  return values.reduce((latest, value) => timestampNanoseconds(value) > timestampNanoseconds(latest) ? value : latest);
}

function parseArtifact(bytes) {
  const text = decodeUtf8(bytes);
  rejectDuplicateJsonKeys(text);
  return JSON.parse(text);
}

function allocateId(used, reserved) {
  for (let number = 1; number <= 999; number += 1) {
    const id = `E${String(number).padStart(3, "0")}`;
    if (!used.has(id) && id !== reserved) {
      return id;
    }
  }
  throw new Error("K0 evidence ID space is exhausted");
}

async function issueFromSnapshot(plan, credentials) {
  const github = plan.github;
  const checkpointResult = await collectGitHubEvidenceCheckpoint({
    owner: github.owner,
    repository: github.repository,
    pullNumber: github.checkpoint_pull_number,
    receiptPath: github.receipt_path,
    archivePath: github.archive_path,
    installationToken: credentials.installationToken,
  });
  const archive = await expandK0PreDisableArchive(checkpointResult.archiveBytes);
  const fragment = structuredClone(archive.fragment);
  const scope = structuredClone(archive.scope);
  if (checkpointResult.checkpoint.owner_id !== scope.owner_id
      || checkpointResult.checkpoint.repository_id !== scope.repository_id
      || checkpointResult.checkpoint.archive.transaction_id !== archive.metadata.transaction_id
      || checkpointResult.checkpoint.archive.nonce !== archive.metadata.nonce
      || checkpointResult.checkpoint.archive.sha256 !== createHash("sha256").update(checkpointResult.archiveBytes).digest("hex")
      || checkpointResult.checkpoint.archive.ledger_sha256 !== archive.metadata.ledger_sha256
      || checkpointResult.checkpoint.archive.artifact_bytes_sha256 !== archive.metadata.artifact_bytes_sha256
      || checkpointResult.checkpoint.archive.sealed_at !== archive.metadata.sealed_at) {
    throw new Error("checkpoint archive identity does not match the verified archive");
  }

  const keyReader = createGoogleKeyReaderObserved({ auth: credentials.googleAuth });
  const gcp = createGcpEvidenceReader({ auth: credentials.googleAuth });
  const disabledKey = await keyReader({
    client_email: scope.service_account_email,
    private_key_id: scope.key_id,
    expected_disabled: true,
  });
  const disableAudit = await gcp.readDisableAuditEntryObserved({
    projectId: scope.project_id,
    projectNumber: scope.project_number,
    serviceAccountEmail: scope.service_account_email,
    serviceAccountUniqueId: scope.service_account_unique_id,
    keyResource: `projects/-/serviceAccounts/${scope.service_account_email}/keys/${scope.key_id}`,
    humanActor: plan.gcp.disable_actor,
    startTime: checkpointResult.checkpoint.run.completed_at,
    endTime: disabledKey.observedAt,
  });
  const legacy = await collectFreshLegacyDenialEvidence({
    owner: github.owner,
    repository: github.repository,
    runId: github.legacy_run_id,
    installationToken: credentials.installationToken,
    scopeOwnerId: scope.owner_id,
    scopeRepositoryId: scope.repository_id,
    keyId: scope.key_id,
  });
  const wif2 = await collectGitHubSuccessfulDeploy({
    owner: github.owner,
    repository: github.repository,
    runId: github.wif2_run_id,
    workflowPath: scope.workflow_path,
    environment: "production",
    installationToken: credentials.installationToken,
  });
  const wif2Revision = await gcp.readNamedCloudRunRevision({
    projectId: scope.project_id,
    region: scope.region,
    service: scope.allowed_service,
    revision: fragment.revisions.wif_2,
    expectedReleaseMarker: wif2.githubRun.release_marker,
  });
  const wifAudit = await gcp.readWifAuditEvidenceObserved({
    projectId: scope.project_id,
    provider: fragment.wif.provider,
    serviceAccountEmail: scope.service_account_email,
    serviceAccountUniqueId: scope.service_account_unique_id,
    startTime: wif2.githubRun.started_at,
    endTime: wif2Revision.create_time,
  });
  const forbiddenBefore = parseArtifact(archive.readArtifact(fragment.revisions.forbidden_after_hostile_source_id));
  const forbidden = await gcp.readExactCloudRunRevisionObservation({
    projectId: scope.project_id,
    region: scope.region,
    service: scope.forbidden_service,
    revision: fragment.revisions.forbidden_after,
    expectedReleaseMarker: forbiddenBefore.data.release_marker,
    expectedCreateTime: forbiddenBefore.data.create_time,
    expectedImageDigest: forbiddenBefore.data.image_digest,
  });

  const observations = [
    checkpointResult.observedAt, disabledKey.observedAt, disableAudit.observedAt, legacy.observedAt,
    wif2.observedAt, wif2Revision.observed_at, wifAudit.observedAt, forbidden.observed_at,
  ];
  const assembledAt = latestTime(observations);
  const artifacts = new Map();
  const ledger = archive.preEvidence.map((entry) => {
    const bytes = archive.readArtifact(entry.id);
    artifacts.set(entry.id, bytes);
    return structuredClone(entry);
  });
  const used = new Set(ledger.map(({ id }) => id));
  const forbiddenId = fragment.revisions.forbidden_after_source_id;
  if (used.has(forbiddenId) || !/^E\d{3}$/.test(forbiddenId)) {
    throw new Error("final forbidden evidence ID is not reserved by the archive");
  }
  const add = (id, kind, locator, observedAt, data) => {
    if (used.has(id)) throw new Error("K0 evidence ID is duplicated");
    used.add(id);
    const created = createEvidenceArtifact({ id, kind, locator, observed_at: observedAt, data });
    const bytes = Buffer.from(created.artifact);
    artifacts.set(id, bytes);
    ledger.push({ id, kind, locator, observed_at: observedAt, sha256: created.sha256 });
    return id;
  };
  const next = () => allocateId(used, forbiddenId);

  const checkpointId = add(next(), "GITHUB_EVIDENCE_CHECKPOINT", "github:authenticated-checkpoint",
    checkpointResult.observedAt, checkpointResult.checkpoint);
  const disabledKeyId = add(next(), "GCP_IAM_KEY", "gcp:disabled-key", disabledKey.observedAt,
    normalizeGoogleKeyEvidence({ key: disabledKey.key, scope }));
  const disableAuditId = add(next(), "GCP_AUDIT_ENTRY", "gcp:disable-audit", disableAudit.observedAt,
    disableAudit.evidence);
  const legacyRunId = add(next(), "GITHUB_RUN", "github:fresh-legacy-denial-run", legacy.observedAt,
    legacy.githubRun);
  const legacyResultId = add(next(), "GOOGLE_AUTH_RESULT", "github:fresh-legacy-denial-result", legacy.observedAt,
    legacy.googleAuthResult);
  const wif2RunId = add(next(), "GITHUB_RUN", "github:wif-2-run", wif2.observedAt, wif2.githubRun);
  const wif2ReviewId = add(next(), "GITHUB_ENVIRONMENT_REVIEW", "github:wif-2-environment-review",
    wif2.observedAt, wif2.environmentReview);
  const wifAuditText = decodeUtf8(wifAudit.projection);
  rejectDuplicateJsonKeys(wifAuditText);
  const wifAuditId = add(next(), "GCP_WIF_AUDIT_LOG", "gcp:wif-2-audit", wifAudit.observedAt,
    JSON.parse(wifAuditText));
  const wif2RevisionId = add(next(), "CLOUD_RUN_REVISION", "gcp:wif-2-revision", wif2Revision.observed_at,
    Object.fromEntries(Object.entries(wif2Revision).filter(([key]) => key !== "observed_at")));
  add(forbiddenId, "CLOUD_RUN_REVISION", "gcp:forbidden-after", forbidden.observed_at,
    Object.fromEntries(Object.entries(forbidden).filter(([key]) => key !== "observed_at")));

  const manifest = {
    version: 3,
    assembled_at: assembledAt,
    ...fragment,
    checkpoint: { source_id: checkpointId },
    disable: {
      key_id: scope.key_id,
      observed_disabled: true,
      human_actor: plan.gcp.disable_actor,
      service_account_unique_id: scope.service_account_unique_id,
      audit_insert_id: disableAudit.evidence.insert_id,
      audit_timestamp: disableAudit.evidence.timestamp,
      source_ids: [disabledKeyId, disableAuditId],
    },
    legacy_after_disable: {
      run_id: legacy.githubRun.run_id,
      run_attempt: legacy.githubRun.run_attempt,
      head_sha: legacy.githubRun.head_sha,
      fresh_runner: true,
      fresh_online_request: true,
      outcome: "DENIED",
      source_ids: [legacyRunId, legacyResultId],
    },
    post_disable: {
      run_id: wif2.githubRun.run_id,
      run_attempt: wif2.githubRun.run_attempt,
      head_sha: wif2.githubRun.head_sha,
      fresh_runner: true,
      outcome: "SUCCEEDED",
      revision: wif2Revision.revision,
      release_marker: wif2Revision.release_marker,
      source_ids: [wif2RunId, wif2ReviewId, wifAuditId, wif2RevisionId],
    },
    leak_scan: { outcome: "CLEAN", source_ids: [] },
    limitations: [
      "Previously minted access tokens are not proven revoked.",
      "The KMS request is inert; authorization remains RECOLLECTION_REQUIRED.",
    ],
    evidence: ledger,
  };
  const scanId = add(next(), "LEAK_SCAN", "credential-scan:final-bundle", assembledAt,
    createCredentialScan(scope, artifacts));
  manifest.leak_scan.source_ids = [scanId];
  manifest.evidence = ledger.toSorted((left, right) => left.id.localeCompare(right.id));
  await verifyK0Bundle({ manifest, artifacts });
  const manifestBytes = Buffer.from(canonicalJson(manifest));
  const receipt = await createK0Receipt({ manifest, manifestBytes, artifacts });
  await verifyK0Receipt({ receiptBytes: receipt.receiptBytes, manifest, manifestBytes, artifacts });
  const kmsRequest = createKmsSigningRequest(receipt.receiptBytes, plan.kms.key_version);
  const kmsRequestBytes = Buffer.from(canonicalJson(kmsRequest));
  return {
    status: "K0_VERIFIED_RECEIPT_PENDING",
    authorization: "RECOLLECTION_REQUIRED",
    release_ready: false,
    bundle: { manifest, manifestBytes, artifacts },
    receipt,
    kmsRequest,
    kmsRequestBytes,
    manifest_sha256: createHash("sha256").update(manifestBytes).digest("hex"),
    receipt_sha256: createHash("sha256").update(receipt.receiptBytes).digest("hex"),
  };
}

export function issueK0Live(planBytes, credentials) {
  const plan = parseK0LiveRecollectionPlan(planBytes);
  const captured = capturedCredentials(credentials);
  return issueFromSnapshot(plan, captured);
}
