import { createHash } from "node:crypto";

import {
  normalizeCloudRunObservation,
  normalizeGoogleKeyEvidence,
  normalizeProofV2Evidence,
} from "../../src/k0-evidence-normalizer.mjs";
import { createCredentialScan } from "../../src/credential-scan.mjs";
import { canonicalJson, createEvidenceArtifact } from "../../src/evidence-artifact.mjs";
import { verifyPreexistingWifReadback } from "../../src/gcp-evidence.mjs";
import { buildWifPlan } from "../../src/wif-plan.mjs";

function checkpointSourceIds(manifest) {
  return new Set([
    ...manifest.legacy_baseline.source_ids,
    ...manifest.proof.source_ids,
    ...manifest.cutover.source_ids,
    ...manifest.wif.source_ids,
    ...Object.values(manifest.approved_workflows).map(({ source_id: sourceId }) => sourceId),
    ...manifest.hostile_tests.flatMap(({ source_ids: sourceIds }) => sourceIds),
  ]);
}

function encodeCheckpointReceipt(receipt) {
  const bytes = Buffer.from(canonicalJson(receipt));
  return {
    bytes,
    blob_sha: createHash("sha1").update(Buffer.concat([Buffer.from(`blob ${bytes.length}\0`), bytes])).digest("hex"),
    sha256: createHash("sha256").update(bytes).digest("hex"),
    bytes_base64: bytes.toString("base64"),
  };
}

export function validWifAuditLog({ scope, wif }) {
  const stsMethod = "google.identity.sts.v1.SecurityTokenService.ExchangeToken";
  const serviceAccount = `projects/-/serviceAccounts/${scope.service_account_email}`;
  return Buffer.from(canonicalJson({
    entries: [{
      insertId: "sts-auth-1",
      timestamp: "2026-08-13T12:13:20Z",
      protoPayload: {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        authenticationInfo: { principalSubject: wif.idp_subject },
        metadata: { mapped_principal: wif.mapped_principal },
        methodName: stsMethod,
        request: {
          "@type": "type.googleapis.com/google.identity.sts.v1.ExchangeTokenRequest",
          grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
        },
        resourceName: wif.provider,
      },
      resource: {
        type: "audited_resource",
        labels: { method: stsMethod, project_id: scope.project_id, service: "sts.googleapis.com" },
      },
    }, {
      insertId: "iam-auth-1",
      timestamp: "2026-08-13T12:13:30Z",
      protoPayload: {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        authenticationInfo: { principalSubject: wif.mapped_principal },
        methodName: "GenerateAccessToken",
        request: {
          "@type": "type.googleapis.com/google.iam.credentials.v1.GenerateAccessTokenRequest",
          name: serviceAccount,
        },
        resourceName: `projects/-/serviceAccounts/${scope.service_account_unique_id}`,
        serviceName: "iamcredentials.googleapis.com",
        status: {},
      },
      resource: {
        type: "service_account",
        labels: {
          email_id: scope.service_account_email,
          project_id: scope.project_id,
          unique_id: scope.service_account_unique_id,
        },
      },
    }],
  }));
}

export function validK0BundleInput() {
  const evidence = [];
  const manifest = {
    version: 3,
    assembled_at: "2026-08-13T12:20:00.123456789Z",
    scope: {
      owner_id: "1",
      repository_id: "2",
      workflow_path: ".github/workflows/k0-deploy.yml",
      proof_workflow_path: ".github/workflows/k0-proof-v2.yml",
      legacy_workflow_path: ".github/workflows/k0-legacy-auth-check.yml",
      h1_workflow_path: ".github/workflows/k0-deploy.yml",
      h2_workflow_path: ".github/workflows/k0-external-hostile.yml",
      h4_workflow_path: ".github/workflows/k0-hostile-wrong-workflow.yml",
      project_id: "example-project",
      project_number: "3",
      region: "us-central1",
      service_account_email: "deploy@example.iam.gserviceaccount.com",
      service_account_unique_id: "110652672782847439596",
      key_id: "a".repeat(40),
      allowed_service: "keyless-demo",
      forbidden_service: "keyless-forbidden",
    },
    revisions: {
      legacy_1: "keyless-demo-legacy-1",
      wif_1: "keyless-demo-wif-1",
      wif_2: "keyless-demo-wif-2",
      forbidden_before: "forbidden-00001",
      forbidden_after: "forbidden-00001",
    },
    approved_workflows: {
      baseline: {
        workflow_path: ".github/workflows/k0-deploy.yml",
        workflow_blob_sha: "62ec226833a2ac44913044ab665a01b0f0f271db",
        workflow_sha256: "efa494890963b2744b031a54f78f13df5575b948eec9fa2ec452342fda6feebf",
      },
      h1: {
        workflow_path: ".github/workflows/k0-deploy.yml",
        workflow_blob_sha: "1".repeat(40),
        workflow_sha256: "1".repeat(64),
      },
      h2: {
        workflow_path: ".github/workflows/k0-external-hostile.yml",
        workflow_blob_sha: "4".repeat(40),
        workflow_sha256: "4".repeat(64),
      },
      h4: {
        workflow_path: ".github/workflows/k0-hostile-wrong-workflow.yml",
        workflow_blob_sha: "2".repeat(40),
        workflow_sha256: "2".repeat(64),
      },
      legacy: {
        workflow_path: ".github/workflows/k0-legacy-auth-check.yml",
        workflow_blob_sha: "3".repeat(40),
        workflow_sha256: "3".repeat(64),
      },
    },
    proof: {
      challenge_status: "CONSUMED",
      challenge_id: "abcdef01-1234-4123-8123-123456789abc",
      proof_digest: "b".repeat(64),
      key_id: "a".repeat(40),
      receipt_sha256: "9".repeat(64),
    },
    cutover: {
      pr_number: 11,
      reviewed_head_sha: "8".repeat(40),
      merge_sha: "9".repeat(40),
      wif_1_run_id: "1501",
      wif_1_run_attempt: "1",
      wif_1_head_sha: "9".repeat(40),
      workflow_blob_sha: "6".repeat(40),
      workflow_sha256: "6".repeat(64),
      wif_1_release_marker: "wif-1",
    },
    wif: {
      mode: "PREEXISTING_EXACT",
      no_added_downstream_permissions: true,
      provider: "projects/3/locations/global/workloadIdentityPools/keyless/providers/github",
      config_hash: "c".repeat(64),
      parity_hash: "d".repeat(64),
      idp_subject: "repo:owner/repo:environment:production",
      mapped_principal: "principal://iam.googleapis.com/projects/3/locations/global/workloadIdentityPools/keyless/subject/repo:owner/repo:environment:production",
    },
    hostile_tests: [],
    legacy_baseline: {
      run_id: "1401",
      run_attempt: "1",
      head_sha: "d".repeat(40),
      fresh_runner: true,
      outcome: "SUCCEEDED",
      revision: "keyless-demo-legacy-1",
      release_marker: "legacy-1",
    },
    disable: {
      key_id: "a".repeat(40),
      observed_disabled: true,
      human_actor: "key-operator@example.com",
      service_account_unique_id: "110652672782847439596",
      audit_insert_id: "audit-1",
      audit_timestamp: "2026-08-13T12:10:00Z",
    },
    legacy_after_disable: {
      run_id: "3001",
      run_attempt: "1",
      head_sha: "e".repeat(40),
      fresh_runner: true,
      fresh_online_request: true,
      outcome: "DENIED",
    },
    post_disable: {
      run_id: "3002",
      run_attempt: "1",
      head_sha: "e".repeat(40),
      fresh_runner: true,
      outcome: "SUCCEEDED",
      revision: "keyless-demo-wif-2",
      release_marker: "wif-2",
    },
    leak_scan: { outcome: "CLEAN" },
    limitations: ["Previously minted access tokens are not proven revoked."],
  };
  const source = (kind, name, data, observedAt = "2026-08-13T12:00:00Z") => {
    const id = `E${String(evidence.length + 1).padStart(3, "0")}`;
    evidence.push({
      id,
      kind,
      locator: `${kind.toLowerCase()}:${name}`,
      observed_at: observedAt,
      public_url: `https://example.test/evidence/${id}`,
      data,
    });
    return id;
  };
  const githubRun = (runId, overrides = {}) => ({
    run_id: runId,
    run_attempt: "1",
    head_sha: "f".repeat(40),
    workflow_path: manifest.scope.workflow_path,
    workflow_ref: `owner/repo/${manifest.scope.workflow_path}@refs/heads/main`,
    owner_id: manifest.scope.owner_id,
    repository_id: manifest.scope.repository_id,
    event: "push",
    ref: "refs/heads/main",
    environment: "production",
    conclusion: "success",
    runner_environment: "github-hosted",
    started_at: "2026-08-13T11:30:00Z",
    workflow_blob_sha: manifest.cutover.workflow_blob_sha,
    workflow_sha256: manifest.cutover.workflow_sha256,
    actor_id: "10",
    release_marker: "wif-1",
    ...overrides,
  });
  const environmentReview = (run) => ({
    run_id: run.run_id,
    run_attempt: run.run_attempt,
    head_sha: run.head_sha,
    environment: run.environment,
    actor_id: run.actor_id,
    reviewer_id: "11",
    state: "approved",
  });
  const gcpScope = {
    project_id: manifest.scope.project_id,
    project_number: manifest.scope.project_number,
    service_account_email: manifest.scope.service_account_email,
    service_account_unique_id: manifest.scope.service_account_unique_id,
  };
  const wifPlan = buildWifPlan({
    project_id: manifest.scope.project_id,
    project_number: manifest.scope.project_number,
    pool_id: "keyless",
    provider_id: "github",
    owner_id: manifest.scope.owner_id,
    repository_id: manifest.scope.repository_id,
    owner: "owner",
    repository: "repo",
    service_account: manifest.scope.service_account_email,
  });
  manifest.wif.provider = wifPlan.provider;
  manifest.wif.config_hash = wifPlan.provider_config_hash;
  const provider = {
    name: wifPlan.provider,
    state: "ACTIVE",
    oidc: { issuerUri: wifPlan.issuer, allowedAudiences: [] },
    attributeMapping: wifPlan.attribute_mapping,
    attributeCondition: wifPlan.attribute_condition,
  };
  const serviceAccountPolicy = {
    version: 1,
    etag: "service-etag-1",
    bindings: [{
      role: wifPlan.impersonation_binding.role,
      members: [wifPlan.impersonation_binding.member],
    }, {
      role: "roles/iam.serviceAccountAdmin",
      members: ["user:key-operator@example.com"],
    }],
  };
  const allowedPolicy = {
    version: 1,
    etag: "allowed-etag-1",
    bindings: [{
      role: "roles/run.developer",
      members: [`serviceAccount:${manifest.scope.service_account_email}`],
    }],
  };
  const forbiddenPolicy = { version: 1, etag: "forbidden-etag-1", bindings: [] };
  const wifParity = verifyPreexistingWifReadback({
    plan: {
      ...wifPlan,
      allowed_service: manifest.scope.allowed_service,
      forbidden_service: manifest.scope.forbidden_service,
    },
    serviceAccountUniqueId: manifest.scope.service_account_unique_id,
    region: manifest.scope.region,
    providerBefore: provider,
    providerAfter: structuredClone(provider),
    serviceAccountPolicyBefore: serviceAccountPolicy,
    serviceAccountPolicyAfter: structuredClone(serviceAccountPolicy),
    allowedPolicyBefore: allowedPolicy,
    allowedPolicyAfter: structuredClone(allowedPolicy),
    forbiddenPolicyBefore: forbiddenPolicy,
    forbiddenPolicyAfter: structuredClone(forbiddenPolicy),
    observedBeforeAt: "2026-08-13T11:00:00Z",
    observedAfterAt: "2026-08-13T12:00:00Z",
  });
  manifest.wif.parity_hash = wifParity.parity_hash;
  const revisionScope = {
    project_id: manifest.scope.project_id,
    region: manifest.scope.region,
  };
  const cloudRevision = (service, revision, releaseMarker, createTime) => normalizeCloudRunObservation({
    ...revisionScope,
    service,
    revision,
    create_time: createTime,
    release_marker: releaseMarker,
    image_digest: `sha256:${"a".repeat(64)}`,
  });

  const forbiddenBefore = source("CLOUD_RUN_REVISION", "forbidden-before",
    cloudRevision(manifest.scope.forbidden_service, manifest.revisions.forbidden_before, "stable", "2026-08-12T10:00:00Z"),
    "2026-08-13T11:00:00Z");
  const forbiddenAfterHostile = source("CLOUD_RUN_REVISION", "forbidden-after-hostile",
    cloudRevision(manifest.scope.forbidden_service, manifest.revisions.forbidden_after, "stable", "2026-08-12T10:00:00Z"),
    "2026-08-13T12:09:00Z");
  const forbiddenAfter = source("CLOUD_RUN_REVISION", "forbidden-after",
    cloudRevision(manifest.scope.forbidden_service, manifest.revisions.forbidden_after, "stable", "2026-08-12T10:00:00Z"),
    "2026-08-13T12:15:00Z");
  const allowedRevision = source("CLOUD_RUN_REVISION", "allowed-after-hostile",
    cloudRevision(manifest.scope.allowed_service, "allowed-00001", "stable", "2026-08-12T10:00:00Z"),
    "2026-08-13T12:09:00Z");
  manifest.revisions.forbidden_before_source_id = forbiddenBefore;
  manifest.revisions.forbidden_after_hostile_source_id = forbiddenAfterHostile;
  manifest.revisions.forbidden_after_source_id = forbiddenAfter;

  const approvalIdentity = {
    baseline: { number: 6, head: "0", merge: "a", owner: manifest.scope.owner_id, repository: manifest.scope.repository_id },
    h1: { number: 7, head: "1", merge: "4", owner: "999", repository: "998" },
    h2: { number: 8, head: "4", merge: "5", owner: manifest.scope.owner_id, repository: "999" },
    h4: { number: 9, head: "2", merge: "6", owner: manifest.scope.owner_id, repository: manifest.scope.repository_id },
    legacy: { number: 10, head: "3", merge: "7", owner: manifest.scope.owner_id, repository: manifest.scope.repository_id },
  };
  for (const [role, approval] of Object.entries(manifest.approved_workflows)) {
    const identity = approvalIdentity[role];
    const reviewedAt = role === "baseline" ? "2026-08-13T10:43:00Z" : "2026-08-13T10:53:00Z";
    const mergedAt = role === "baseline" ? "2026-08-13T10:44:00Z" : "2026-08-13T10:54:00Z";
    approval.source_id = source("GITHUB_PULL_REQUEST", `${role}-workflow-approval`, {
      number: identity.number,
      head_sha: identity.head.repeat(40),
      merge_sha: identity.merge.repeat(40),
      workflow_path: approval.workflow_path,
      workflow_blob_sha: approval.workflow_blob_sha,
      workflow_sha256: approval.workflow_sha256,
      owner_id: identity.owner,
      repository_id: identity.repository,
      author_id: "20",
      reviewer_id: "21",
      review_commit_sha: identity.head.repeat(40),
      reviewed_at: reviewedAt,
      merged_at: mergedAt,
      merged: true,
      reviewed: true,
    }, role === "baseline" ? "2026-08-13T10:45:00Z" : "2026-08-13T10:55:00Z");
  }

  const baselineRun = githubRun(manifest.legacy_baseline.run_id, {
    run_attempt: manifest.legacy_baseline.run_attempt,
    head_sha: manifest.legacy_baseline.head_sha,
    event: "workflow_dispatch",
    started_at: "2026-08-13T10:46:00Z",
    release_marker: manifest.legacy_baseline.release_marker,
    workflow_blob_sha: manifest.approved_workflows.baseline.workflow_blob_sha,
    workflow_sha256: manifest.approved_workflows.baseline.workflow_sha256,
  });
  manifest.legacy_baseline.source_ids = [
    source("GITHUB_RUN", "legacy-baseline", baselineRun, "2026-08-13T10:48:00Z"),
    source("GITHUB_ENVIRONMENT_REVIEW", "legacy-baseline-review", environmentReview(baselineRun), "2026-08-13T10:48:00Z"),
    source("GCP_IAM_KEY", "legacy-baseline-key", normalizeGoogleKeyEvidence({
      key: {
        name: `projects/-/serviceAccounts/${manifest.scope.service_account_email}/keys/${manifest.scope.key_id}`,
        keyType: "USER_MANAGED", keyAlgorithm: "KEY_ALG_RSA_2048", disabled: false,
      },
      scope: gcpScope,
    }), "2026-08-13T10:48:00Z"),
    source("CLOUD_RUN_REVISION", "legacy-baseline-revision", cloudRevision(
      manifest.scope.allowed_service,
      manifest.revisions.legacy_1,
      manifest.legacy_baseline.release_marker,
      "2026-08-13T10:47:00Z",
    ), "2026-08-13T10:48:00Z"),
  ];

  const hostileCases = {
    H1: ["WRONG_OWNER_ID", "WIF_PROVIDER_CONDITION"],
    H2: ["WRONG_REPOSITORY_ID", "WIF_PROVIDER_CONDITION"],
    H3: ["WRONG_REF", "WIF_PROVIDER_CONDITION"],
    H4: ["WRONG_WORKFLOW_REF", "WIF_PROVIDER_CONDITION"],
    H5: ["WRONG_EVENT", "WIF_PROVIDER_CONDITION"],
    H6: ["WRONG_ENVIRONMENT", "WIF_PROVIDER_CONDITION"],
    H7: ["WRONG_AUDIENCE", "STS_AUDIENCE"],
    H8: ["FORBIDDEN_RESOURCE", "CLOUD_RUN_IAM"],
  };
  manifest.hostile_tests = Object.entries(hostileCases).map(([id, [identity_case, expected_control]]) => {
    const number = id.slice(1);
    const run = githubRun(`200${number}`);
    if (id === "H1") {
      run.owner_id = "999";
      run.repository_id = "998";
    }
    if (id === "H2") run.repository_id = "999";
    if (["H1", "H2"].includes(id)) {
      const role = id.toLowerCase();
      run.workflow_path = manifest.scope[`${role}_workflow_path`];
      run.workflow_ref = `owner/repo/${run.workflow_path}@refs/heads/main`;
      run.workflow_blob_sha = manifest.approved_workflows[role].workflow_blob_sha;
      run.workflow_sha256 = manifest.approved_workflows[role].workflow_sha256;
      run.release_marker = "external";
    }
    if (id === "H3") {
      run.ref = "refs/heads/keyless-h3";
      run.workflow_ref = "owner/repo/.github/workflows/k0-deploy.yml@refs/heads/keyless-h3";
    }
    if (id === "H4") {
      run.workflow_path = manifest.scope.h4_workflow_path;
      run.workflow_ref = `owner/repo/${manifest.scope.h4_workflow_path}@refs/heads/main`;
      run.workflow_blob_sha = manifest.approved_workflows.h4.workflow_blob_sha;
      run.workflow_sha256 = manifest.approved_workflows.h4.workflow_sha256;
    }
    if (id === "H5") run.event = "workflow_dispatch";
    if (id === "H6") run.environment = "staging";
    const runSource = source("GITHUB_RUN", `${id}-run`, run);
    const resultSource = id === "H8"
      ? source("CLOUD_RUN_IAM_RESULT", `${id}-result`, {
        hostile_id: id,
        run_id: run.run_id,
        run_attempt: run.run_attempt,
        head_sha: run.head_sha,
        outcome: "DENIED",
        reached_cloud_run: true,
        target: manifest.scope.forbidden_service,
        denied_at: "2026-08-13T11:50:00Z",
        log_sha256: "2".repeat(64),
      })
      : source("STS_CLIENT_RESULT", `${id}-result`, {
        hostile_id: id,
        run_id: run.run_id,
        run_attempt: run.run_attempt,
        head_sha: run.head_sha,
        outcome: "DENIED",
        reached_sts: true,
        error_category: id === "H7" ? "AUDIENCE_DENIED" : "WIF_CONDITION_DENIED",
        denied_at: "2026-08-13T11:50:00Z",
        log_sha256: "1".repeat(64),
      });
    return {
      id,
      identity_case,
      expected_control,
      reached_control: true,
      outcome: "DENIED",
      target_revision_before: id === "H8" ? manifest.revisions.forbidden_before : "allowed-00001",
      target_revision_after: id === "H8" ? manifest.revisions.forbidden_after : "allowed-00001",
      source_ids: [runSource, resultSource, ...(id === "H8" ? [forbiddenBefore, forbiddenAfterHostile] : [allowedRevision])],
    };
  });

  const proofRun = githubRun("1001", {
    head_sha: "7".repeat(40),
    workflow_path: manifest.scope.proof_workflow_path,
    workflow_ref: `owner/repo/${manifest.scope.proof_workflow_path}@refs/heads/main`,
    workflow_blob_sha: "5".repeat(40),
    workflow_sha256: "5".repeat(64),
    event: "workflow_dispatch",
  });
  const proofEvidence = normalizeProofV2Evidence({
    observation: {
      ...proofRun,
      event_name: proofRun.event,
      environment_review: { state: "approved", environment: "production", reviewer_id: "11" },
    },
    receipt: {
      challenge_id: manifest.proof.challenge_id,
      proof_digest: manifest.proof.proof_digest,
      key_id: manifest.scope.key_id,
      run_id: proofRun.run_id,
      verified: true,
      consumed: true,
    },
  });
  manifest.proof.source_ids = [
    source("GITHUB_RUN", "proof-run", proofEvidence.githubRun),
    source("GITHUB_ENVIRONMENT_REVIEW", "proof-review", proofEvidence.environmentReview),
    source("PROOFV2_ARTIFACT", "proof-artifact", proofEvidence.proofArtifact),
    source("PROOFV2_CHALLENGE_STATE", "proof-challenge-state", {
      version: 3,
      status: "CONSUMED",
      verified: true,
      consumed: true,
      replay_rejected: true,
      replay_evidence: "ORIGINAL_OPERATOR_RECEIPT_ONLY",
      migration_id: "migration-001",
      challenge_id: manifest.proof.challenge_id,
      proof_digest: manifest.proof.proof_digest,
      key_id: manifest.scope.key_id,
      owner_id: manifest.scope.owner_id,
      repository_id: manifest.scope.repository_id,
      workflow_path: manifest.scope.proof_workflow_path,
      event_name: "workflow_dispatch",
      ref: "refs/heads/main",
      environment: "production",
      client_email: manifest.scope.service_account_email,
      run_id: proofRun.run_id,
      run_attempt: proofRun.run_attempt,
      head_sha: proofRun.head_sha,
      run_started_at: proofRun.started_at,
      issued_at: "2026-08-13T11:29:00Z",
      expires_at: "2026-08-13T11:34:00Z",
      consumed_at: "2026-08-13T11:32:00Z",
      update_time: "2026-08-13T11:32:01Z",
      receipt_sha256: manifest.proof.receipt_sha256,
    }, "2026-08-13T11:32:02Z"),
    source("GCP_IAM_KEY", "proof-key", normalizeGoogleKeyEvidence({
      key: {
        name: `projects/-/serviceAccounts/${manifest.scope.service_account_email}/keys/${manifest.scope.key_id}`,
        keyType: "USER_MANAGED", keyAlgorithm: "KEY_ALG_RSA_2048", disabled: false,
      },
      scope: gcpScope,
    })),
  ];
  const wif1Run = githubRun(manifest.cutover.wif_1_run_id, {
    run_attempt: manifest.cutover.wif_1_run_attempt,
    head_sha: manifest.cutover.wif_1_head_sha,
    release_marker: manifest.cutover.wif_1_release_marker,
  });
  manifest.cutover.source_ids = [
    source("GITHUB_PULL_REQUEST", "cutover-pr", {
      number: manifest.cutover.pr_number,
      head_sha: manifest.cutover.reviewed_head_sha,
      merge_sha: manifest.cutover.merge_sha,
      workflow_path: manifest.scope.workflow_path,
      workflow_blob_sha: manifest.cutover.workflow_blob_sha,
      workflow_sha256: manifest.cutover.workflow_sha256,
      owner_id: manifest.scope.owner_id,
      repository_id: manifest.scope.repository_id,
      author_id: "20",
      reviewer_id: "21",
      review_commit_sha: manifest.cutover.reviewed_head_sha,
      reviewed_at: "2026-08-13T10:56:00Z",
      merged_at: "2026-08-13T10:57:00Z",
      merged: true,
      reviewed: true,
    }),
    source("GITHUB_RUN", "wif-1", wif1Run),
    source("GITHUB_ENVIRONMENT_REVIEW", "wif-1-review", environmentReview(wif1Run)),
    source("CLOUD_RUN_REVISION", "wif-1-revision", cloudRevision(
      manifest.scope.allowed_service,
      manifest.revisions.wif_1,
      manifest.cutover.wif_1_release_marker,
      "2026-08-13T11:31:00Z",
    )),
  ];
  manifest.wif.source_ids = [
    source("GCP_WIF_PARITY", "preexisting-exact", wifParity, wifParity.observed_after_at),
  ];
  const checkpointedIds = checkpointSourceIds(manifest);
  const receipt = encodeCheckpointReceipt({
    version: 1,
    evidence: evidence.filter(({ id }) => checkpointedIds.has(id)).map(({ id, kind, locator, observed_at, data }) => ({
      id,
      kind,
      locator,
      recorded_at: observed_at,
      data_sha256: createHash("sha256").update(canonicalJson(data)).digest("hex"),
    })).toSorted((left, right) => left.id.localeCompare(right.id)),
  });
  manifest.checkpoint = {
    source_id: source("GITHUB_EVIDENCE_CHECKPOINT", "reviewed-pre-disable-receipt", {
      owner_id: manifest.scope.owner_id,
      repository_id: manifest.scope.repository_id,
      collected_at: "2026-08-13T12:18:00Z",
      protection: {
        branch: "main",
        required_status_checks_strict: true,
        required_check_name: "test",
        required_check_app_id: "15368",
        required_approving_review_count: 1,
        dismiss_stale_reviews: true,
        require_last_push_approval: true,
        enforce_admins: true,
        required_linear_history: true,
      },
      pull: {
        number: 12,
        head_sha: "b".repeat(40),
        merge_sha: "c".repeat(40),
        author_id: "20",
        reviewer_id: "21",
        review_commit_sha: "b".repeat(40),
        reviewed_at: "2026-08-13T12:09:01Z",
        merged_at: "2026-08-13T12:09:05Z",
      },
      receipt: {
        path: "docs/evidence/K0_CHECKPOINT_EXAMPLE.json",
        blob_sha: receipt.blob_sha,
        sha256: receipt.sha256,
        bytes_base64: receipt.bytes_base64,
      },
      archive: {
        path: "docs/evidence/K0_PREDISABLE_ARCHIVE_EXAMPLE.json",
        blob_sha: "d".repeat(40),
        sha256: "d".repeat(64),
        ledger_sha256: "e".repeat(64),
        artifact_bytes_sha256: "f".repeat(64),
        sealed_at: "2026-08-13T12:00:00Z",
        transaction_id: "example-transaction-1",
        nonce: "example-public-nonce-0001",
      },
      run: {
        run_id: "4001",
        run_attempt: "1",
        head_sha: "c".repeat(40),
        workflow_path: ".github/workflows/ci.yml",
        event: "push",
        ref: "refs/heads/main",
        status: "completed",
        conclusion: "success",
        started_at: "2026-08-13T12:09:10Z",
        completed_at: "2026-08-13T12:09:45Z",
      },
      check: {
        name: "test",
        app_id: "15368",
        app_slug: "github-actions",
        head_sha: "c".repeat(40),
        status: "completed",
        conclusion: "success",
        started_at: "2026-08-13T12:09:15Z",
        completed_at: "2026-08-13T12:09:40Z",
        details_url: "https://github.com/owner/repo/actions/runs/4001/job/5001",
      },
    }, "2026-08-13T12:18:00Z"),
  };
  manifest.disable.source_ids = [
    source("GCP_IAM_KEY", "disabled-key", normalizeGoogleKeyEvidence({
      key: {
        name: `projects/-/serviceAccounts/${manifest.scope.service_account_email}/keys/${manifest.scope.key_id}`,
        keyType: "USER_MANAGED", keyAlgorithm: "KEY_ALG_RSA_2048", disabled: true,
      },
      scope: gcpScope,
    }), "2026-08-13T12:10:30Z"),
    source("GCP_AUDIT_ENTRY", "disable-entry", {
      method_name: "google.iam.admin.v1.DisableServiceAccountKey",
      resource_name: `projects/-/serviceAccounts/${manifest.disable.service_account_unique_id}/keys/${manifest.scope.key_id}`,
      key_id: manifest.scope.key_id,
      service_account_email: manifest.scope.service_account_email,
      service_account_unique_id: manifest.disable.service_account_unique_id,
      project_id: manifest.scope.project_id,
      project_number: manifest.scope.project_number,
      principal_email: manifest.disable.human_actor,
      insert_id: manifest.disable.audit_insert_id,
      timestamp: manifest.disable.audit_timestamp,
      status: "SUCCEEDED",
    }, "2026-08-13T12:10:30Z"),
  ];
  manifest.legacy_after_disable.source_ids = [
    source("GITHUB_RUN", "legacy-denied", githubRun(manifest.legacy_after_disable.run_id, {
      head_sha: manifest.legacy_after_disable.head_sha,
      workflow_path: ".github/workflows/k0-legacy-auth-check.yml",
      workflow_ref: "owner/repo/.github/workflows/k0-legacy-auth-check.yml@refs/heads/main",
      event: "workflow_dispatch",
      runner_environment: "github-hosted",
      started_at: "2026-08-13T12:11:00Z",
      workflow_blob_sha: manifest.approved_workflows.legacy.workflow_blob_sha,
      workflow_sha256: manifest.approved_workflows.legacy.workflow_sha256,
      release_marker: null,
    }), "2026-08-13T12:12:00Z"),
    source("GOOGLE_AUTH_RESULT", "legacy-auth", {
      key_id: manifest.scope.key_id,
      run_id: manifest.legacy_after_disable.run_id,
      run_attempt: manifest.legacy_after_disable.run_attempt,
      head_sha: manifest.legacy_after_disable.head_sha,
      owner_id: manifest.scope.owner_id,
      repository_id: manifest.scope.repository_id,
      workflow_path: manifest.scope.legacy_workflow_path,
      workflow_ref: `owner/repo/${manifest.scope.legacy_workflow_path}@refs/heads/main`,
      ref: "refs/heads/main",
      outcome: "DENIED",
      fresh_runner: true,
      fresh_online_request: true,
      reached_google: true,
      rejection_category: "DISABLED_OR_INVALID_KEY",
      rejected_at: "2026-08-13T12:11:30Z",
      log_sha256: "3".repeat(64),
    }, "2026-08-13T12:12:00Z"),
  ];
  const wif2Run = githubRun(manifest.post_disable.run_id, {
    run_attempt: manifest.post_disable.run_attempt,
    head_sha: manifest.post_disable.head_sha,
    started_at: "2026-08-13T12:13:00Z",
    release_marker: manifest.post_disable.release_marker,
  });
  manifest.post_disable.source_ids = [
    source("GITHUB_RUN", "wif-2", wif2Run, "2026-08-13T12:14:00Z"),
    source("GITHUB_ENVIRONMENT_REVIEW", "wif-2-review", environmentReview(wif2Run), "2026-08-13T12:14:00Z"),
    source("GCP_WIF_AUDIT_LOG", "wif-2-audit", JSON.parse(validWifAuditLog(manifest)), "2026-08-13T12:14:00Z"),
    source("CLOUD_RUN_REVISION", "wif-2-revision", cloudRevision(
      manifest.scope.allowed_service,
      manifest.revisions.wif_2,
      manifest.post_disable.release_marker,
      "2026-08-13T12:13:45Z",
    ), "2026-08-13T12:14:00Z"),
  ];
  const finalArtifacts = new Map(evidence.map((envelope) => [
    envelope.id,
    Buffer.from(createEvidenceArtifact(envelope).artifact),
  ]));
  const finalScanId = source(
    "LEAK_SCAN",
    "final-bundle",
    createCredentialScan(manifest.scope, finalArtifacts),
    "2026-08-13T12:16:00Z",
  );
  evidence.find(({ id }) => id === finalScanId).locator = "credential-scan:final-bundle";
  manifest.leak_scan.source_ids = [finalScanId];

  return { manifest, evidence };
}

export function evidenceByKind(input, kind, name) {
  return input.evidence.find((item) => item.kind === kind && (!name || item.locator.endsWith(`:${name}`)));
}

export function mutateCheckpointReceipt(input, mutate) {
  const checkpoint = evidenceByKind(input, "GITHUB_EVIDENCE_CHECKPOINT").data;
  const receipt = JSON.parse(Buffer.from(checkpoint.receipt.bytes_base64, "base64").toString("utf8"));
  mutate(receipt);
  const encoded = encodeCheckpointReceipt(receipt);
  checkpoint.receipt.blob_sha = encoded.blob_sha;
  checkpoint.receipt.sha256 = encoded.sha256;
  checkpoint.receipt.bytes_base64 = encoded.bytes_base64;
}

export function refreshCheckpointReceipt(input) {
  const previous = new Map(JSON.parse(Buffer.from(
    evidenceByKind(input, "GITHUB_EVIDENCE_CHECKPOINT").data.receipt.bytes_base64,
    "base64",
  ).toString("utf8")).evidence.map((record) => [record.id, record]));
  const ids = checkpointSourceIds(input.manifest);
  mutateCheckpointReceipt(input, (receipt) => {
    receipt.evidence = input.evidence.filter(({ id }) => ids.has(id)).map(({ id, kind, locator, observed_at, data }) => ({
      id,
      kind,
      locator,
      recorded_at: previous.get(id)?.recorded_at ?? observed_at,
      data_sha256: createHash("sha256").update(canonicalJson(data)).digest("hex"),
    })).toSorted((left, right) => left.id.localeCompare(right.id));
  });
}

export function refreshFinalCredentialScan(input) {
  const scanId = input.manifest.leak_scan.source_ids[0];
  const scan = input.evidence.find(({ id }) => id === scanId);
  if (!scan || scan.kind !== "LEAK_SCAN") throw new Error("fixture final credential scan is missing");
  const artifacts = new Map(input.evidence
    .filter(({ kind }) => kind !== "LEAK_SCAN")
    .map((envelope) => [envelope.id, Buffer.from(createEvidenceArtifact(envelope).artifact)]));
  scan.data = createCredentialScan(input.manifest.scope, artifacts);
  return input;
}
