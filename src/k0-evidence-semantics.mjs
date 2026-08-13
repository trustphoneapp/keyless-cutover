import { verifyEvidenceArtifacts } from "./evidence-artifact.mjs";

const SHA256 = /^[a-f0-9]{64}$/;
const KEY_ID = /^[a-f0-9]{40}$/;
const NUMERIC = /^\d+$/;
const REVISION = /^[a-z][a-z0-9-]{0,62}$/;

function string(value, pattern) {
  return typeof value === "string" && value.length > 0 && value.length <= 2048 && (!pattern || pattern.test(value));
}

function object(value) {
  return value && typeof value === "object" && !Array.isArray(value);
}

function validateArtifactData(kind, data, fail, id) {
  fail(object(data), `${id} data must be an object`);
  if (!object(data)) return;
  if (kind === "GITHUB_RUN") {
    fail(string(data.run_id, NUMERIC) && string(data.run_attempt, NUMERIC), `${id} GitHub run identity is invalid`);
    fail(string(data.head_sha, /^[a-f0-9]{40}$/) && string(data.workflow_path) && string(data.workflow_ref), `${id} GitHub workflow identity is invalid`);
    fail(string(data.owner_id, NUMERIC) && string(data.repository_id, NUMERIC), `${id} GitHub repository identity is invalid`);
    fail(string(data.event) && string(data.ref) && string(data.environment) && ["success", "failure"].includes(data.conclusion), `${id} GitHub run result is invalid`);
  } else if (kind === "GITHUB_ENVIRONMENT_REVIEW") {
    fail(string(data.run_id, NUMERIC) && string(data.environment), `${id} environment review scope is invalid`);
    fail(string(data.actor_id, NUMERIC) && string(data.reviewer_id, NUMERIC) && data.actor_id !== data.reviewer_id, `${id} environment review is not independent`);
    fail(data.state === "approved", `${id} environment review was not approved`);
  } else if (kind === "PROOFV2_ARTIFACT") {
    fail(string(data.challenge_id) && string(data.proof_digest, SHA256) && string(data.key_id, KEY_ID), `${id} ProofV2 data is invalid`);
    fail(data.verified === true && data.consumed === true, `${id} ProofV2 was not verified and consumed`);
  } else if (kind === "GCP_IAM_KEY") {
    fail(string(data.key_id, KEY_ID) && string(data.name), `${id} Google key identity is invalid`);
    fail(data.key_type === "USER_MANAGED" && data.algorithm === "KEY_ALG_RSA_2048", `${id} Google key type is invalid`);
    fail(typeof data.disabled === "boolean", `${id} Google key state is invalid`);
  } else if (kind === "GCP_WIF_PROVIDER") {
    fail(string(data.name) && string(data.config_hash, SHA256) && data.state === "ACTIVE", `${id} WIF provider data is invalid`);
  } else if (kind === "GCP_IAM_POLICY") {
    fail(string(data.policy_hash, SHA256) && string(data.iam_diff_hash, SHA256) && string(data.etag), `${id} IAM policy data is invalid`);
    fail(data.no_added_downstream_permissions === true, `${id} IAM policy widened downstream permissions`);
  } else if (kind === "STS_CLIENT_RESULT") {
    fail(/^H[1-7]$/.test(data.hostile_id ?? "") && string(data.run_id, NUMERIC), `${id} STS hostile identity is invalid`);
    fail(data.outcome === "DENIED" && data.reached_sts === true, `${id} did not prove an STS denial`);
    fail(["WIF_CONDITION_DENIED", "AUDIENCE_DENIED"].includes(data.error_category), `${id} STS denial category is invalid`);
  } else if (kind === "CLOUD_RUN_IAM_RESULT") {
    fail(data.hostile_id === "H8" && string(data.run_id, NUMERIC) && string(data.target, REVISION), `${id} Cloud Run hostile identity is invalid`);
    fail(data.outcome === "DENIED" && data.reached_cloud_run === true, `${id} did not prove a Cloud Run IAM denial`);
  } else if (kind === "CLOUD_RUN_REVISION") {
    fail(string(data.service, REVISION) && string(data.revision, REVISION), `${id} Cloud Run revision data is invalid`);
  } else if (kind === "GCP_AUDIT_ENTRY") {
    fail(string(data.method_name) && string(data.resource_name) && string(data.principal_email), `${id} audit entry data is invalid`);
  } else if (kind === "GOOGLE_AUTH_RESULT") {
    fail(string(data.key_id, KEY_ID) && string(data.run_id, NUMERIC), `${id} legacy-auth identity is invalid`);
    fail(data.outcome === "DENIED" && data.fresh_runner === true && data.fresh_online_request === true, `${id} legacy denial was not fresh and online`);
  } else if (kind === "LEAK_SCAN") {
    fail(data.outcome === "CLEAN" && string(data.scanner) && string(data.scope_hash, SHA256), `${id} leak scan data is invalid`);
  }
}

export async function verifyK0EvidenceSemantics(manifest, readArtifact) {
  const integrity = await verifyEvidenceArtifacts(manifest, readArtifact);
  if (!integrity.ok) return integrity;
  const errors = [];
  const fail = (condition, message) => { if (!condition) errors.push(message); };
  const entries = new Map(manifest.evidence.map((entry) => [entry.id, entry]));
  const artifacts = new Map();
  for (const entry of manifest.evidence) {
    const parsed = JSON.parse((await readArtifact(entry.id)).toString());
    artifacts.set(entry.id, parsed);
    validateArtifactData(entry.kind, parsed.data, fail, entry.id);
  }
  const dataOfKind = (ids, kind) => ids
    .filter((id) => entries.get(id)?.kind === kind)
    .map((id) => artifacts.get(id)?.data);

  const proofData = dataOfKind(manifest.proof.source_ids, "PROOFV2_ARTIFACT");
  fail(proofData.some((data) => data?.challenge_id === manifest.proof.challenge_id
    && data?.proof_digest === manifest.proof.proof_digest && data?.key_id === manifest.scope.key_id), "ProofV2 artifact does not match the manifest claim");
  const proofKeys = dataOfKind(manifest.proof.source_ids, "GCP_IAM_KEY");
  fail(proofKeys.some((data) => data?.key_id === manifest.scope.key_id && data?.disabled === false), "ProofV2 key was not observed active");

  const providers = dataOfKind(manifest.wif.source_ids, "GCP_WIF_PROVIDER");
  fail(providers.some((data) => data?.name === manifest.wif.provider && data?.config_hash === manifest.wif.config_hash), "WIF provider artifact does not match");
  const policies = dataOfKind(manifest.wif.source_ids, "GCP_IAM_POLICY");
  fail(policies.some((data) => data?.iam_diff_hash === manifest.wif.iam_diff_hash
    && data?.no_added_downstream_permissions === true), "WIF IAM artifact does not match");

  for (const hostile of manifest.hostile_tests) {
    const resultKind = hostile.id === "H8" ? "CLOUD_RUN_IAM_RESULT" : "STS_CLIENT_RESULT";
    const results = dataOfKind(hostile.source_ids, resultKind);
    const expectedCategory = hostile.id === "H7" ? "AUDIENCE_DENIED" : "WIF_CONDITION_DENIED";
    fail(results.some((data) => data?.hostile_id === hostile.id && data?.outcome === hostile.outcome
      && (hostile.id === "H8" ? data?.target === manifest.scope.forbidden_service : data?.error_category === expectedCategory)), `${hostile.id} client artifact does not match`);
    const runs = dataOfKind(hostile.source_ids, "GITHUB_RUN");
    fail(runs.some((run) => results.some((result) => result?.run_id === run?.run_id)), `${hostile.id} client result is not bound to its GitHub run`);
    const expectedWorkflowRef = `${manifest.scope.workflow_path}@refs/heads/main`;
    const contextMatches = runs.some((run) => {
      if (hostile.id === "H1") return run.owner_id !== manifest.scope.owner_id;
      if (hostile.id === "H2") return run.owner_id === manifest.scope.owner_id && run.repository_id !== manifest.scope.repository_id;
      if (hostile.id === "H3") return run.ref !== "refs/heads/main";
      if (hostile.id === "H4") return !run.workflow_ref.endsWith(expectedWorkflowRef);
      if (hostile.id === "H5") return run.event !== "push";
      if (hostile.id === "H6") return run.environment !== "production";
      return run.owner_id === manifest.scope.owner_id && run.repository_id === manifest.scope.repository_id
        && run.ref === "refs/heads/main" && run.event === "push" && run.environment === "production"
        && run.workflow_ref.endsWith(expectedWorkflowRef);
    });
    fail(contextMatches, `${hostile.id} GitHub identity case is not evidenced`);
    const revisions = dataOfKind(hostile.source_ids, "CLOUD_RUN_REVISION");
    fail(revisions.some((data) => data?.revision === hostile.target_revision_before
      && data?.revision === hostile.target_revision_after), `${hostile.id} unchanged target revision is not evidenced`);
  }

  const disabledKeys = dataOfKind(manifest.disable.source_ids, "GCP_IAM_KEY");
  fail(disabledKeys.some((data) => data?.key_id === manifest.scope.key_id && data?.disabled === true), "disabled-key artifact does not match");
  const disableAudits = dataOfKind(manifest.disable.source_ids, "GCP_AUDIT_ENTRY");
  fail(disableAudits.some((data) => data?.principal_email === manifest.disable.human_actor
    && /DisableServiceAccountKey/.test(data?.method_name ?? "")), "human disable audit artifact does not match");

  const legacy = dataOfKind(manifest.legacy_after_disable.source_ids, "GOOGLE_AUTH_RESULT");
  fail(legacy.some((data) => data?.key_id === manifest.scope.key_id && data?.outcome === "DENIED"), "fresh legacy-auth artifact does not match");
  const postRevisions = dataOfKind(manifest.post_disable.source_ids, "CLOUD_RUN_REVISION");
  fail(postRevisions.some((data) => data?.service === manifest.scope.allowed_service
    && data?.revision === manifest.revisions.wif_2), "post-disable Cloud Run revision artifact does not match");
  return { ok: errors.length === 0, errors };
}
