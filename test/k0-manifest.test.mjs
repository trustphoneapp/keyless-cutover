import assert from "node:assert/strict";
import test from "node:test";

import { verifyK0Manifest } from "../src/k0-manifest.mjs";

function validManifest() {
  return {
    version: 1,
    scope: {
      owner_id: "1",
      repository_id: "2",
      workflow_path: ".github/workflows/deploy.yml",
      project_number: "3",
      service_account_email: "deploy@example.iam.gserviceaccount.com",
      key_id: "a".repeat(40),
      allowed_service: "keyless-demo",
      forbidden_service: "keyless-forbidden",
    },
    revisions: {
      legacy_1: "legacy-1-abc",
      wif_1: "wif-1-def",
      wif_2: "wif-2-ghi",
      forbidden_before: "forbidden-00001",
      forbidden_after: "forbidden-00001",
    },
    proof: {
      challenge_status: "CONSUMED",
      challenge_id: "challenge-1",
      proof_digest: "digest-1",
      key_id: "a".repeat(40),
      source_ids: ["github-run:1", "gcp-key:a"],
    },
    wif: {
      no_added_downstream_permissions: true,
      provider: "projects/3/locations/global/workloadIdentityPools/keyless/providers/github",
      config_hash: "config-hash",
      iam_diff_hash: "iam-diff-hash",
      source_ids: ["gcp-provider:github", "gcp-policy:etag-1"],
    },
    hostile_tests: Object.entries({
      H1: "WIF_PROVIDER_CONDITION",
      H2: "WIF_PROVIDER_CONDITION",
      H3: "WIF_PROVIDER_CONDITION",
      H4: "WIF_PROVIDER_CONDITION",
      H5: "WIF_PROVIDER_CONDITION",
      H6: "WIF_PROVIDER_CONDITION",
      H7: "STS_AUDIENCE",
      H8: "CLOUD_RUN_IAM",
    }).map(([id, expected_control]) => ({
      id,
      expected_control,
      reached_control: true,
      outcome: "DENIED",
      source_ids: [`github-run:${id}`],
    })),
    disable: {
      key_id: "a".repeat(40),
      observed_disabled: true,
      human_actor: "key-operator@example.com",
      source_ids: ["gcp-audit:disable-1", "gcp-key-read:a"],
    },
    legacy_after_disable: {
      fresh_runner: true,
      fresh_online_request: true,
      outcome: "DENIED",
      source_ids: ["github-run:legacy-denied"],
    },
    post_disable: {
      fresh_runner: true,
      outcome: "SUCCEEDED",
      revision: "wif-2-ghi",
      source_ids: ["github-run:wif-2", "cloud-run-revision:wif-2-ghi"],
    },
    leak_scan: { outcome: "CLEAN", source_ids: ["ci-job:leak-scan"] },
    limitations: ["Previously minted access tokens are not proven revoked."],
  };
}

test("K0 manifest requires every external proof and rejects false-safe variants", () => {
  assert.deepEqual(verifyK0Manifest(validManifest()), { ok: true, errors: [] });

  for (const mutate of [
    (m) => { m.hostile_tests[3].reached_control = false; },
    (m) => { m.hostile_tests[7].outcome = "NOT_RUN"; },
    (m) => { m.revisions.forbidden_after = "changed"; },
    (m) => { m.disable.key_id = "b".repeat(40); },
    (m) => { m.legacy_after_disable.fresh_online_request = false; },
    (m) => { m.post_disable.revision = "stale"; },
    (m) => { m.leak_scan.source_ids = ["-----BEGIN PRIVATE KEY-----"]; },
  ]) {
    const manifest = validManifest();
    mutate(manifest);
    assert.equal(verifyK0Manifest(manifest).ok, false);
  }
});
