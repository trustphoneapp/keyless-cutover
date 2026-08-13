import assert from "node:assert/strict";
import test from "node:test";

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
  const revision = source("CLOUD_RUN_REVISION", "allowed-before-hostile");
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
      revision,
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
