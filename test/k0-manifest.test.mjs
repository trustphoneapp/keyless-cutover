import assert from "node:assert/strict";
import test from "node:test";

import { createEvidenceArtifact, verifyEvidenceArtifacts } from "../src/evidence-artifact.mjs";
import { verifyK0EvidenceSemantics } from "../src/k0-evidence-semantics.mjs";
import { verifyK0Manifest } from "../src/k0-manifest.mjs";

function validManifest() {
  const evidence = [];
  const source = (kind, name) => {
    const id = `E${String(evidence.length + 1).padStart(3, "0")}`;
    evidence.push({
      id,
      kind,
      locator: `${kind.toLowerCase()}:${name}`,
      observed_at: "2026-08-13T12:00:00Z",
      sha256: String(evidence.length % 10).repeat(64),
      public_url: `https://example.test/evidence/${id}`,
    });
    return id;
  };
  const allowedRevision = source("CLOUD_RUN_REVISION", "allowed-before-hostile");
  const forbiddenRevision = source("CLOUD_RUN_REVISION", "forbidden-before-hostile");
  const hostiles = Object.entries({
    H1: ["WRONG_OWNER_ID", "WIF_PROVIDER_CONDITION"],
    H2: ["WRONG_REPOSITORY_ID", "WIF_PROVIDER_CONDITION"],
    H3: ["WRONG_REF", "WIF_PROVIDER_CONDITION"],
    H4: ["WRONG_WORKFLOW_REF", "WIF_PROVIDER_CONDITION"],
    H5: ["WRONG_EVENT", "WIF_PROVIDER_CONDITION"],
    H6: ["WRONG_ENVIRONMENT", "WIF_PROVIDER_CONDITION"],
    H7: ["WRONG_AUDIENCE", "STS_AUDIENCE"],
    H8: ["FORBIDDEN_RESOURCE", "CLOUD_RUN_IAM"],
  }).map(([id, [identity_case, expected_control]]) => ({
    id,
    identity_case,
    expected_control,
    reached_control: true,
    outcome: "DENIED",
    target_revision_before: id === "H8" ? "forbidden-00001" : "allowed-00001",
    target_revision_after: id === "H8" ? "forbidden-00001" : "allowed-00001",
    source_ids: [
      source("GITHUB_RUN", `${id}-run`),
      source(id === "H8" ? "CLOUD_RUN_IAM_RESULT" : "STS_CLIENT_RESULT", `${id}-result`),
      id === "H8" ? forbiddenRevision : allowedRevision,
    ],
  }));
  return {
    version: 2,
    scope: {
      owner_id: "1",
      repository_id: "2",
      workflow_path: ".github/workflows/k0-deploy.yml",
      project_number: "3",
      service_account_email: "deploy@example.iam.gserviceaccount.com",
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
    evidence,
    proof: {
      challenge_status: "CONSUMED",
      challenge_id: "challenge-1",
      proof_digest: "b".repeat(64),
      key_id: "a".repeat(40),
      source_ids: [
        source("GITHUB_RUN", "proof-run"),
        source("GITHUB_ENVIRONMENT_REVIEW", "proof-review"),
        source("PROOFV2_ARTIFACT", "proof-artifact"),
        source("GCP_IAM_KEY", "proof-key"),
      ],
    },
    wif: {
      no_added_downstream_permissions: true,
      provider: "projects/3/locations/global/workloadIdentityPools/keyless/providers/github",
      config_hash: "c".repeat(64),
      iam_diff_hash: "d".repeat(64),
      source_ids: [source("GCP_WIF_PROVIDER", "provider"), source("GCP_IAM_POLICY", "policy")],
    },
    hostile_tests: hostiles,
    disable: {
      key_id: "a".repeat(40),
      observed_disabled: true,
      human_actor: "key-operator@example.com",
      source_ids: [source("GCP_IAM_KEY", "disabled-key"), source("GCP_AUDIT_ENTRY", "disable-entry")],
    },
    legacy_after_disable: {
      fresh_runner: true,
      fresh_online_request: true,
      outcome: "DENIED",
      source_ids: [source("GITHUB_RUN", "legacy-denied"), source("GOOGLE_AUTH_RESULT", "legacy-auth")],
    },
    post_disable: {
      fresh_runner: true,
      outcome: "SUCCEEDED",
      revision: "keyless-demo-wif-2",
      source_ids: [source("GITHUB_RUN", "wif-2"), source("CLOUD_RUN_REVISION", "wif-2-revision")],
    },
    leak_scan: { outcome: "CLEAN", source_ids: [source("LEAK_SCAN", "credential-scan")] },
    limitations: ["Previously minted access tokens are not proven revoked."],
  };
}

test("K0 manifest resolves every security claim to typed hashed evidence", () => {
  const manifest = validManifest();
  assert.deepEqual(verifyK0Manifest(manifest), { ok: true, errors: [] });

  for (const mutate of [
    (value) => { value.hostile_tests[3].reached_control = false; },
    (value) => { value.hostile_tests[7].outcome = "NOT_RUN"; },
    (value) => { value.hostile_tests[0].identity_case = "WRONG_REF"; },
    (value) => { value.hostile_tests[0].target_revision_after = "changed"; },
    (value) => { value.revisions.forbidden_after = "changed"; },
    (value) => { value.disable.key_id = "b".repeat(40); },
    (value) => { value.legacy_after_disable.fresh_online_request = false; },
    (value) => { value.post_disable.revision = "stale"; },
    (value) => { value.evidence.find(({ kind }) => kind === "STS_CLIENT_RESULT").kind = "GITHUB_RUN"; },
    (value) => { value.evidence.push({ ...value.evidence[0], id: "E099" }); },
    (value) => { value.evidence[0].locator = "-----BEGIN PRIVATE KEY-----"; },
  ]) {
    const changed = validManifest();
    mutate(changed);
    assert.equal(verifyK0Manifest(changed).ok, false);
  }
});

test("K0 evidence ledger resolves to canonical artifact bytes", async () => {
  const manifest = validManifest();
  const artifacts = new Map();
  const dataFor = (entry) => {
    const suffix = entry.locator.split(":").at(-1);
    if (entry.kind === "GITHUB_RUN") {
      const hostile = suffix.match(/h[1-8]/i)?.[0].toUpperCase();
      const number = hostile?.slice(1);
      const value = {
        run_id: hostile ? `200${number}` : "1001", run_attempt: "1", head_sha: "a".repeat(40),
        workflow_path: ".github/workflows/k0-deploy.yml", workflow_ref: "owner/repo/.github/workflows/k0-deploy.yml@refs/heads/main",
        owner_id: "1", repository_id: "2", event: "push", ref: "refs/heads/main", environment: "production", conclusion: "success",
      };
      if (hostile === "H1") value.owner_id = "999";
      if (hostile === "H2") value.repository_id = "999";
      if (hostile === "H3") {
        value.ref = "refs/heads/keyless-h3";
        value.workflow_ref = "owner/repo/.github/workflows/k0-deploy.yml@refs/heads/keyless-h3";
      }
      if (hostile === "H4") {
        value.workflow_path = ".github/workflows/k0-hostile-wrong-workflow.yml";
        value.workflow_ref = "owner/repo/.github/workflows/k0-hostile-wrong-workflow.yml@refs/heads/main";
      }
      if (hostile === "H5") value.event = "workflow_dispatch";
      if (hostile === "H6") value.environment = "staging";
      return value;
    }
    if (entry.kind === "GITHUB_ENVIRONMENT_REVIEW") return { run_id: "1001", environment: "production", actor_id: "10", reviewer_id: "11", state: "approved" };
    if (entry.kind === "PROOFV2_ARTIFACT") return { challenge_id: manifest.proof.challenge_id, proof_digest: manifest.proof.proof_digest, key_id: manifest.scope.key_id, verified: true, consumed: true };
    if (entry.kind === "GCP_IAM_KEY") return { name: `projects/-/serviceAccounts/${manifest.scope.service_account_email}/keys/${manifest.scope.key_id}`, key_id: manifest.scope.key_id, key_type: "USER_MANAGED", algorithm: "KEY_ALG_RSA_2048", disabled: suffix.includes("disabled") };
    if (entry.kind === "GCP_WIF_PROVIDER") return { name: manifest.wif.provider, config_hash: manifest.wif.config_hash, state: "ACTIVE" };
    if (entry.kind === "GCP_IAM_POLICY") return { policy_hash: "e".repeat(64), iam_diff_hash: manifest.wif.iam_diff_hash, etag: "etag-1", no_added_downstream_permissions: true };
    if (entry.kind === "STS_CLIENT_RESULT") {
      const hostile_id = suffix.match(/h[1-7]/i)[0].toUpperCase();
      return { hostile_id, run_id: `200${hostile_id.slice(1)}`, outcome: "DENIED", reached_sts: true, error_category: hostile_id === "H7" ? "AUDIENCE_DENIED" : "WIF_CONDITION_DENIED", log_sha256: "1".repeat(64) };
    }
    if (entry.kind === "CLOUD_RUN_IAM_RESULT") return { hostile_id: "H8", run_id: "2008", outcome: "DENIED", reached_cloud_run: true, target: manifest.scope.forbidden_service, log_sha256: "2".repeat(64) };
    if (entry.kind === "CLOUD_RUN_REVISION") return suffix.includes("wif-2")
      ? { service: manifest.scope.allowed_service, revision: manifest.revisions.wif_2 }
      : suffix.includes("forbidden")
        ? { service: manifest.scope.forbidden_service, revision: manifest.revisions.forbidden_before }
        : { service: manifest.scope.allowed_service, revision: "allowed-00001" };
    if (entry.kind === "GCP_AUDIT_ENTRY") return { method_name: "google.iam.admin.v1.DisableServiceAccountKey", resource_name: `keys/${manifest.scope.key_id}`, principal_email: manifest.disable.human_actor };
    if (entry.kind === "GOOGLE_AUTH_RESULT") return { key_id: manifest.scope.key_id, run_id: "3001", outcome: "DENIED", fresh_runner: true, fresh_online_request: true, log_sha256: "3".repeat(64) };
    if (entry.kind === "LEAK_SCAN") return { outcome: "CLEAN", scanner: "gitleaks", scope_hash: "f".repeat(64) };
    throw new Error(`unhandled kind ${entry.kind}`);
  };
  for (const entry of manifest.evidence) {
    const created = createEvidenceArtifact({
      id: entry.id,
      kind: entry.kind,
      locator: entry.locator,
      observed_at: entry.observed_at,
      data: dataFor(entry),
    });
    entry.sha256 = created.sha256;
    artifacts.set(entry.id, created.artifact);
  }
  assert.equal(verifyK0Manifest(manifest).ok, true);
  assert.deepEqual(await verifyEvidenceArtifacts(manifest, async (id) => artifacts.get(id)), { ok: true, errors: [] });
  assert.deepEqual(await verifyK0EvidenceSemantics(manifest, async (id) => artifacts.get(id)), { ok: true, errors: [] });
  artifacts.set("E001", artifacts.get("E001").replace("allowed-00001", "changed-00001"));
  assert.equal((await verifyEvidenceArtifacts(manifest, async (id) => artifacts.get(id))).ok, false);
});
