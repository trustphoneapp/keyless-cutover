import { createHash } from "node:crypto";

import { assertCredentialFreeBytes } from "./credential-scan.mjs";
import { canonicalJson, createEvidenceArtifact, decodeUtf8 } from "./evidence-artifact.mjs";
import { createGcpEvidenceReader } from "./gcp-evidence.mjs";
import { collectGitHubDenialEvidence } from "./github-denial-evidence.mjs";
import { collectSuccessfulLegacyDeploy } from "./github-legacy-evidence.mjs";
import { collectGitHubSuccessfulDeploy, collectGitHubWorkflowApproval } from "./github-positive-evidence.mjs";
import { requireGitHubReadToken } from "./github-token.mjs";
import { createGoogleKeyReader, createGoogleKeyReaderObserved } from "./google-key-reader.mjs";
import {
  normalizeGoogleKeyEvidence,
  normalizeProofV2Evidence,
  parseGitHubEvidenceCheckpointReceipt,
} from "./k0-evidence-normalizer.mjs";
import { verifyK0PreDisableEvidenceSemantics } from "./k0-evidence-semantics.mjs";
import { HOSTILE_CASES, SCOPE_FIELDS } from "./k0-manifest.mjs";
import { parseK0PreDisableArchivePlanBytes } from "./k0-predisable-archive.mjs";
import { collectProofV2, collectReadOnlyConsumedProofV2State } from "./proofv2-operator.mjs";
import { isRfc3339 } from "./rfc3339.mjs";
import { buildWifPlan } from "./wif-plan.mjs";

const DOMAIN = "KEYLESS_K0_PREDISABLE_COLLECT_PLAN_V1";
const MAX_PLAN = 32 * 1024;
const MAX_RECEIPT = 64 * 1024;
const MAX_OBSERVATION = 8 * 1024;
const PLAN_FIELDS = new Set([
  "version", "domain", "transaction_id", "nonce", "github", "scope", "wif", "planned_wif_2_revision",
  "legacy_baseline", "proof", "cutover", "approvals", "hostile", "forbidden_target",
]);
const GITHUB_FIELDS = new Set(["owner", "repository"]);
const WIF_FIELDS = new Set(["pool_id", "provider_id"]);
const PROOF_FIELDS = new Set(["run_id"]);
const RUN_PULL_FIELDS = new Set(["run_id", "pull_number"]);
const APPROVAL_FIELDS = new Set(["owner", "repository", "pull_number"]);
const HOSTILE_FIELDS = new Set(["owner", "repository", "run_id"]);
const TARGET_FIELDS = new Set(["revision", "release_marker", "create_time", "image_digest"]);
const APPROVAL_ROLES = ["h1", "h2", "h4", "legacy"];
const HOSTILE_IDS = ["H1", "H2", "H3", "H4", "H5", "H6", "H7", "H8"];
const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}$/;
const NUMERIC = /^\d+$/;
const RESOURCE_ID = /^[a-z][a-z0-9-]{3,31}$/;
const SERVICE = /^[a-z][a-z0-9-]{0,62}$/;
const RELEASE_MARKER = /^[a-z0-9][a-z0-9-]{0,19}$/;
const IMAGE_DIGEST = /^sha256:[a-f0-9]{64}$/;

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

function pullNumber(value, name) {
  if (!Number.isInteger(value) || value < 1) throw new Error(`${name} is invalid`);
  return value;
}

export function parseK0PreDisableCollectPlan(planBytes) {
  if (!Buffer.isBuffer(planBytes) || !planBytes.length || planBytes.length > MAX_PLAN) {
    throw new Error("pre-disable collect plan bytes are invalid");
  }
  const captured = Buffer.from(planBytes);
  assertCredentialFreeBytes(captured);
  let plan;
  try {
    plan = JSON.parse(decodeUtf8(captured));
  } catch {
    throw new Error("pre-disable collect plan is not JSON");
  }
  if (!captured.equals(Buffer.from(canonicalJson(plan), "utf8")) || !exactObject(plan, PLAN_FIELDS)
      || plan.version !== 1 || plan.domain !== DOMAIN || !exactObject(plan.github, GITHUB_FIELDS)
      || !exactObject(plan.scope, SCOPE_FIELDS) || !exactObject(plan.wif, WIF_FIELDS)
      || !exactObject(plan.proof, PROOF_FIELDS) || !exactObject(plan.legacy_baseline, RUN_PULL_FIELDS)
      || !exactObject(plan.cutover, RUN_PULL_FIELDS) || !exactObject(plan.forbidden_target, TARGET_FIELDS)
      || !exactObject(plan.approvals, new Set(APPROVAL_ROLES))
      || !exactObject(plan.hostile, new Set(HOSTILE_IDS))) {
    throw new Error("pre-disable collect plan is invalid");
  }
  exact(plan.transaction_id, /^[a-z0-9][a-z0-9-]{0,63}$/, "transaction ID");
  exact(plan.nonce, /^[A-Za-z0-9_-]{16,128}$/, "nonce");
  exact(plan.github.owner, OWNER, "GitHub owner");
  exact(plan.github.repository, REPOSITORY, "GitHub repository");
  exact(plan.wif.pool_id, RESOURCE_ID, "WIF pool ID");
  exact(plan.wif.provider_id, RESOURCE_ID, "WIF provider ID");
  exact(plan.planned_wif_2_revision, SERVICE, "planned wif-2 revision");
  exact(plan.proof.run_id, NUMERIC, "ProofV2 run ID");
  for (const [name, value] of [["legacy baseline", plan.legacy_baseline], ["cutover", plan.cutover]]) {
    exact(value.run_id, NUMERIC, `${name} run ID`);
    pullNumber(value.pull_number, `${name} pull number`);
  }
  for (const role of APPROVAL_ROLES) {
    const approval = plan.approvals[role];
    if (!exactObject(approval, APPROVAL_FIELDS)) throw new Error(`${role} workflow approval is invalid`);
    exact(approval.owner, OWNER, `${role} workflow approval owner`);
    exact(approval.repository, REPOSITORY, `${role} workflow approval repository`);
    pullNumber(approval.pull_number, `${role} workflow approval pull number`);
  }
  for (const id of HOSTILE_IDS) {
    const hostile = plan.hostile[id];
    if (!exactObject(hostile, HOSTILE_FIELDS)) throw new Error(`${id} hostile run is invalid`);
    exact(hostile.owner, OWNER, `${id} hostile owner`);
    exact(hostile.repository, REPOSITORY, `${id} hostile repository`);
    exact(hostile.run_id, NUMERIC, `${id} hostile run ID`);
  }
  exact(plan.forbidden_target.revision, SERVICE, "forbidden target revision");
  exact(plan.forbidden_target.release_marker, RELEASE_MARKER, "forbidden target release marker");
  exact(plan.forbidden_target.image_digest, IMAGE_DIGEST, "forbidden target image digest");
  return plan;
}

const OBSERVATION_FIELDS = new Set([
  "project_id", "region", "service", "revision", "create_time", "release_marker", "image_digest", "observed_at",
]);

function forbiddenTargetOf(plan) {
  return {
    projectId: plan.scope.project_id,
    region: plan.scope.region,
    service: plan.scope.forbidden_service,
    revision: plan.forbidden_target.revision,
    expectedReleaseMarker: plan.forbidden_target.release_marker,
    expectedCreateTime: plan.forbidden_target.create_time,
    expectedImageDigest: plan.forbidden_target.image_digest,
  };
}

// Phase one. Must run BEFORE the first hostile probe starts: k0-evidence-semantics requires this
// observation strictly before H8's run_started_at, and the phase-two plan needs H8's run ID, so the
// two cannot happen in one command.
export async function observeK0ForbiddenBefore(planBytes, credentials) {
  const plan = parseK0PreDisableCollectPlan(planBytes);
  const gcp = createGcpEvidenceReader({
    auth: credentials?.googleAuth,
    fetchImpl: credentials?.fetchImpl ?? fetch,
  });
  const bytes = Buffer.from(canonicalJson(await gcp.readExactCloudRunRevisionObservation(forbiddenTargetOf(plan))));
  assertCredentialFreeBytes(bytes);
  return bytes;
}

export function parseK0ForbiddenBeforeBytes(observationBytes, plan) {
  if (!Buffer.isBuffer(observationBytes) || !observationBytes.length || observationBytes.length > MAX_OBSERVATION) {
    throw new Error("forbidden-before observation bytes are invalid");
  }
  let observation;
  try {
    observation = JSON.parse(decodeUtf8(observationBytes));
  } catch {
    throw new Error("forbidden-before observation is not JSON");
  }
  const target = forbiddenTargetOf(plan);
  if (!observationBytes.equals(Buffer.from(canonicalJson(observation), "utf8"))
      || !exactObject(observation, OBSERVATION_FIELDS)
      || observation.project_id !== target.projectId || observation.region !== target.region
      || observation.service !== target.service || observation.revision !== target.revision
      || observation.release_marker !== target.expectedReleaseMarker
      || observation.create_time !== target.expectedCreateTime
      || observation.image_digest !== target.expectedImageDigest
      || !isRfc3339(observation.observed_at)) {
    throw new Error("forbidden-before observation does not match the approved target");
  }
  return observation;
}

async function collectFromPlan(plan, { token, googleAuth, challengeStore, operatorReceiptBytes, forbiddenBefore, fetchImpl }) {
  const scope = structuredClone(plan.scope);
  const { owner, repository } = plan.github;
  const gcp = createGcpEvidenceReader({ auth: googleAuth, fetchImpl });
  const readKey = createGoogleKeyReaderObserved({ auth: googleAuth, fetchImpl });
  const forbiddenTarget = forbiddenTargetOf(plan);

  // The two forbidden-target reads bracket every hostile run that must not have changed it.
  // The "before" read cannot happen here: k0-evidence-semantics requires it strictly before H8
  // started, and this plan can only be written once H8 exists. Phase one records it instead.

  const legacy = await collectSuccessfulLegacyDeploy({
    owner,
    repository,
    runId: plan.legacy_baseline.run_id,
    pullNumber: plan.legacy_baseline.pull_number,
    installationToken: token,
    fetchImpl,
  });
  const approvals = {};
  for (const role of APPROVAL_ROLES) {
    const request = plan.approvals[role];
    approvals[role] = await collectGitHubWorkflowApproval({
      owner: request.owner,
      repository: request.repository,
      pullNumber: request.pull_number,
      workflowPath: scope[`${role}_workflow_path`],
      installationToken: token,
      fetchImpl,
    });
  }
  const key = await readKey({
    client_email: scope.service_account_email,
    private_key_id: scope.key_id,
    project_id: scope.project_id,
    expected_disabled: false,
  });
  const legacyRevision = await gcp.readNamedCloudRunRevision({
    projectId: scope.project_id,
    region: scope.region,
    service: scope.allowed_service,
    revision: `${scope.allowed_service}-${legacy.githubRun.release_marker}`,
    expectedReleaseMarker: legacy.githubRun.release_marker,
  });

  const collected = await collectProofV2({
    owner,
    repository,
    runId: plan.proof.run_id,
    workflowPath: scope.proof_workflow_path,
    environment: "production",
    token,
    fetchImpl,
  });
  const state = await collectReadOnlyConsumedProofV2State({
    challengeStore,
    proof: collected.proof,
    observed: collected.observed,
    operatorReceiptBytes,
    getGoogleKey: createGoogleKeyReader({ auth: googleAuth, fetchImpl }),
    fetchImpl,
  });
  const proof = normalizeProofV2Evidence({
    observation: collected.observed,
    receipt: state.challengeState,
  });

  const cutoverApproval = await collectGitHubWorkflowApproval({
    owner,
    repository,
    pullNumber: plan.cutover.pull_number,
    workflowPath: scope.workflow_path,
    installationToken: token,
    fetchImpl,
  });
  const wif1 = await collectGitHubSuccessfulDeploy({
    owner,
    repository,
    runId: plan.cutover.run_id,
    workflowPath: scope.workflow_path,
    environment: "production",
    installationToken: token,
    fetchImpl,
  });
  const wif1Revision = await gcp.readNamedCloudRunRevision({
    projectId: scope.project_id,
    region: scope.region,
    service: scope.allowed_service,
    revision: `${scope.allowed_service}-${wif1.githubRun.release_marker}`,
    expectedReleaseMarker: wif1.githubRun.release_marker,
  });
  const parity = await gcp.readPreexistingWifParity({
    plan: {
      ...buildWifPlan({
        project_id: scope.project_id,
        project_number: scope.project_number,
        pool_id: plan.wif.pool_id,
        provider_id: plan.wif.provider_id,
        owner_id: scope.owner_id,
        repository_id: scope.repository_id,
        owner,
        repository,
        service_account: scope.service_account_email,
      }),
      allowed_service: scope.allowed_service,
      forbidden_service: scope.forbidden_service,
    },
    scope,
  });

  const hostile = {};
  for (const id of HOSTILE_IDS) {
    const request = plan.hostile[id];
    hostile[id] = await collectGitHubDenialEvidence({
      owner: request.owner,
      repository: request.repository,
      runId: request.run_id,
      hostileId: id,
      installationToken: token,
      scopeOwnerId: scope.owner_id,
      scopeRepositoryId: scope.repository_id,
      forbiddenService: scope.forbidden_service,
      provider: parity.provider,
      fetchImpl,
    });
  }

  const forbiddenAfterHostile = await gcp.readExactCloudRunRevisionObservation(forbiddenTarget);

  return {
    scope,
    forbiddenBefore,
    forbiddenAfterHostile,
    legacy,
    approvals,
    key,
    legacyRevision,
    proof,
    proofObservedAt: state.observedAt,
    challengeState: state.challengeState,
    cutoverApproval,
    wif1,
    wif1Revision,
    parity,
    hostile,
  };
}

function buildOutputs(plan, collected) {
  const { scope } = collected;
  const evidence = [];
  const add = (kind, locator, observedAt, data) => {
    const id = `E${String(evidence.length + 1).padStart(3, "0")}`;
    evidence.push({ id, kind, locator, observed_at: observedAt, data });
    return id;
  };
  const revisionData = ({ observed_at: _observedAt, ...rest }) => rest;

  const forbiddenBeforeId = add("CLOUD_RUN_REVISION", "gcp:forbidden-before",
    collected.forbiddenBefore.observed_at, revisionData(collected.forbiddenBefore));
  // A merged pull request is immutable, and its merge is the authoritative time of the reviewed fact.
  const approved = Object.fromEntries([
    ["baseline", collected.legacy.workflowApproval, collected.legacy.observedAt],
    ...APPROVAL_ROLES.map((role) => [role, collected.approvals[role], collected.approvals[role].merged_at]),
  ].map(([role, data, observedAt]) => [role, {
    workflow_path: data.workflow_path,
    workflow_blob_sha: data.workflow_blob_sha,
    workflow_sha256: data.workflow_sha256,
    source_id: add("GITHUB_PULL_REQUEST", `github:${role}-workflow-approval`, observedAt, data),
  }]));

  const legacyRunId = add("GITHUB_RUN", "github:legacy-baseline-run",
    collected.legacy.observedAt, collected.legacy.githubRun);
  const legacyReviewId = add("GITHUB_ENVIRONMENT_REVIEW", "github:legacy-baseline-review",
    collected.legacy.observedAt, collected.legacy.environmentReview);
  const keyId = add("GCP_IAM_KEY", "gcp:enabled-key", collected.key.observedAt,
    normalizeGoogleKeyEvidence({ key: collected.key.key, scope }));
  const legacyRevisionId = add("CLOUD_RUN_REVISION", "gcp:legacy-1-revision",
    collected.legacyRevision.observed_at, revisionData(collected.legacyRevision));

  const proofRunId = add("GITHUB_RUN", "github:proof-run", collected.proofObservedAt, collected.proof.githubRun);
  const proofReviewId = add("GITHUB_ENVIRONMENT_REVIEW", "github:proof-review",
    collected.proofObservedAt, collected.proof.environmentReview);
  const proofArtifactId = add("PROOFV2_ARTIFACT", "github:proof-artifact",
    collected.proofObservedAt, collected.proof.proofArtifact);
  const proofStateId = add("PROOFV2_CHALLENGE_STATE", "firestore:proof-challenge-state",
    collected.proofObservedAt, collected.challengeState);

  const cutoverPullId = add("GITHUB_PULL_REQUEST", "github:cutover-pull-request",
    collected.cutoverApproval.merged_at, collected.cutoverApproval);
  const wif1RunId = add("GITHUB_RUN", "github:wif-1-run", collected.wif1.observedAt, collected.wif1.githubRun);
  const wif1ReviewId = add("GITHUB_ENVIRONMENT_REVIEW", "github:wif-1-review",
    collected.wif1.observedAt, collected.wif1.environmentReview);
  const wif1RevisionId = add("CLOUD_RUN_REVISION", "gcp:wif-1-revision",
    collected.wif1Revision.observed_at, revisionData(collected.wif1Revision));
  const parityId = add("GCP_WIF_PARITY", "gcp:preexisting-exact",
    collected.parity.observed_after_at, collected.parity);

  const hostileTests = HOSTILE_IDS.map((id) => {
    const result = collected.hostile[id];
    const runId = add("GITHUB_RUN", `github:${id.toLowerCase()}-run`, result.observedAt, result.githubRun);
    const resultId = add(id === "H8" ? "CLOUD_RUN_IAM_RESULT" : "STS_CLIENT_RESULT",
      `github:${id.toLowerCase()}-result`, result.observedAt, result.clientResult);
    const target = id === "H8" ? plan.forbidden_target.revision : collected.wif1Revision.revision;
    return {
      id,
      identity_case: HOSTILE_CASES[id][0],
      expected_control: HOSTILE_CASES[id][1],
      reached_control: true,
      outcome: "DENIED",
      target_revision_before: target,
      target_revision_after: target,
      source_ids: [runId, resultId],
    };
  });
  const forbiddenAfterHostileId = add("CLOUD_RUN_REVISION", "gcp:forbidden-after-hostile",
    collected.forbiddenAfterHostile.observed_at, revisionData(collected.forbiddenAfterHostile));
  for (const test of hostileTests) {
    test.source_ids.push(...(test.id === "H8"
      ? [forbiddenBeforeId, forbiddenAfterHostileId]
      : [wif1RevisionId]));
  }

  const pool = collected.parity.provider.replace(/\/providers\/[a-z0-9-]+$/, "");
  const idpSubject = `repo:${plan.github.owner}/${plan.github.repository}:environment:production`;
  const fragment = {
    scope,
    revisions: {
      legacy_1: collected.legacyRevision.revision,
      wif_1: collected.wif1Revision.revision,
      wif_2: plan.planned_wif_2_revision,
      forbidden_before: plan.forbidden_target.revision,
      forbidden_after: plan.forbidden_target.revision,
      forbidden_before_source_id: forbiddenBeforeId,
      forbidden_after_hostile_source_id: forbiddenAfterHostileId,
      forbidden_after_source_id: `E${String(evidence.length + 1).padStart(3, "0")}`,
    },
    approved_workflows: approved,
    legacy_baseline: {
      run_id: collected.legacy.githubRun.run_id,
      run_attempt: collected.legacy.githubRun.run_attempt,
      head_sha: collected.legacy.githubRun.head_sha,
      fresh_runner: true,
      outcome: "SUCCEEDED",
      revision: collected.legacyRevision.revision,
      release_marker: collected.legacyRevision.release_marker,
      source_ids: [legacyRunId, legacyReviewId, keyId, legacyRevisionId],
    },
    proof: {
      challenge_status: "CONSUMED",
      challenge_id: collected.challengeState.challenge_id,
      proof_digest: collected.challengeState.proof_digest,
      key_id: collected.challengeState.key_id,
      receipt_sha256: collected.challengeState.receipt_sha256,
      source_ids: [proofRunId, proofReviewId, proofArtifactId, proofStateId, keyId],
    },
    cutover: {
      pr_number: collected.cutoverApproval.number,
      reviewed_head_sha: collected.cutoverApproval.head_sha,
      merge_sha: collected.cutoverApproval.merge_sha,
      wif_1_run_id: collected.wif1.githubRun.run_id,
      wif_1_run_attempt: collected.wif1.githubRun.run_attempt,
      wif_1_head_sha: collected.wif1.githubRun.head_sha,
      workflow_blob_sha: collected.wif1.githubRun.workflow_blob_sha,
      workflow_sha256: collected.wif1.githubRun.workflow_sha256,
      wif_1_release_marker: collected.wif1Revision.release_marker,
      source_ids: [cutoverPullId, wif1RunId, wif1ReviewId, wif1RevisionId],
    },
    wif: {
      mode: "PREEXISTING_EXACT",
      provider: collected.parity.provider,
      config_hash: collected.parity.provider_config_hash,
      parity_hash: collected.parity.parity_hash,
      idp_subject: idpSubject,
      mapped_principal: `principal://iam.googleapis.com/${pool}/subject/${idpSubject}`,
      no_added_downstream_permissions: true,
      source_ids: [parityId],
    },
    hostile_tests: hostileTests,
  };

  const artifacts = new Map();
  const ledger = evidence.map((envelope) => {
    const created = createEvidenceArtifact(envelope);
    artifacts.set(envelope.id, Buffer.from(created.artifact));
    return {
      id: envelope.id,
      kind: envelope.kind,
      locator: envelope.locator,
      observed_at: envelope.observed_at,
      sha256: created.sha256,
    };
  });
  return {
    artifacts,
    bundleInput: { manifest: fragment, evidence },
    archivePlan: {
      version: 1,
      transaction_id: plan.transaction_id,
      nonce: plan.nonce,
      scope: structuredClone(scope),
      fragment,
      evidence: ledger,
    },
    checkpointReceipt: {
      version: 1,
      evidence: evidence.map(({ id, kind, locator, observed_at: observedAt, data }) => ({
        id,
        kind,
        locator,
        recorded_at: observedAt,
        data_sha256: createHash("sha256").update(canonicalJson(data)).digest("hex"),
      })).toSorted((left, right) => left.id.localeCompare(right.id)),
    },
  };
}

export async function collectK0PreDisable(planBytes, credentials) {
  const plan = parseK0PreDisableCollectPlan(planBytes);
  const receiptBytes = Buffer.isBuffer(credentials?.operatorReceiptBytes)
    ? Buffer.from(credentials.operatorReceiptBytes) : null;
  if (!receiptBytes || !receiptBytes.length || receiptBytes.length > MAX_RECEIPT) {
    throw new Error("ProofV2 operator receipt bytes are invalid");
  }
  const collected = await collectFromPlan(plan, {
    token: requireGitHubReadToken(credentials?.installationToken),
    googleAuth: credentials?.googleAuth,
    challengeStore: credentials?.challengeStore,
    operatorReceiptBytes: receiptBytes,
    forbiddenBefore: parseK0ForbiddenBeforeBytes(
      Buffer.isBuffer(credentials?.forbiddenBeforeBytes) ? Buffer.from(credentials.forbiddenBeforeBytes) : null,
      plan,
    ),
    fetchImpl: credentials?.fetchImpl ?? fetch,
  });
  const outputs = buildOutputs(plan, collected);
  const semantic = await verifyK0PreDisableEvidenceSemantics(
    outputs.archivePlan.fragment,
    outputs.archivePlan.evidence,
    async (id) => outputs.artifacts.get(id),
  );
  if (!semantic.ok) throw new Error(semantic.errors.join("\n"));
  const bundleInputBytes = Buffer.from(canonicalJson(outputs.bundleInput));
  const archivePlanBytes = Buffer.from(canonicalJson(outputs.archivePlan));
  const checkpointReceiptBytes = Buffer.from(canonicalJson(outputs.checkpointReceipt));
  parseK0PreDisableArchivePlanBytes(archivePlanBytes);
  parseGitHubEvidenceCheckpointReceipt(checkpointReceiptBytes);
  assertCredentialFreeBytes(bundleInputBytes);
  return { bundleInputBytes, archivePlanBytes, checkpointReceiptBytes };
}
