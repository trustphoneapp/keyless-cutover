import assert from "node:assert/strict";
import test from "node:test";
import AdmZip from "adm-zip";

import { collectFreshLegacyDenialEvidence } from "../src/github-legacy-evidence.mjs";

function response(status, value, extraHeaders = {}) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (name) => extraHeaders[name.toLowerCase()] ?? null },
    text: async () => bytes.toString("utf8"),
    arrayBuffer: async () => bytes,
  };
}

function fixture(log = "gcloud: problem refreshing auth tokens: invalid_grant: Invalid JWT Signature") {
  const keyId = "a".repeat(40);
  const run = {
    id: 9001, run_attempt: 1, status: "completed", conclusion: "success", head_sha: "b".repeat(40),
    head_branch: "main", path: ".github/workflows/k0-legacy-auth-check.yml", event: "workflow_dispatch",
    repository: { id: 2, full_name: "trustphoneapp/keyless-cutover", owner: { id: 1 } },
  };
  const artifact = {
    version: 1, id: "legacy-after-disable", outcome: "failure", key_id: keyId, run_id: "9001", run_attempt: "1",
    head_sha: "b".repeat(40), workflow_ref: "trustphoneapp/keyless-cutover/.github/workflows/k0-legacy-auth-check.yml@refs/heads/main",
    event: "workflow_dispatch", ref: "refs/heads/main", environment: "production", fresh_runner: true, fresh_online_request: true,
  };
  const zip = new AdmZip();
  zip.addFile("k0-legacy-after-disable.json", Buffer.from(JSON.stringify(artifact)));
  const fetchImpl = async (url) => {
    if (url.endsWith("/actions/runs/9001")) return response(200, run);
    if (url.includes("/jobs?")) return response(200, { jobs: [{ id: 91, name: "fresh-legacy-auth", status: "completed", conclusion: "success", steps: [{ name: "Require fresh legacy denial", conclusion: "success" }] }] });
    if (url.includes("/artifacts?")) return response(200, { artifacts: [{ id: 92, name: "keyless-legacy-after-disable", expired: false }] });
    if (url.endsWith("/actions/artifacts/92/zip")) return response(302, "", { location: "https://objects.githubusercontent.com/legacy.zip" });
    if (url.endsWith("/actions/jobs/91/logs")) return response(302, "", { location: "https://objects.githubusercontent.com/legacy.txt" });
    if (url.endsWith("legacy.zip")) return response(200, zip.toBuffer());
    if (url.endsWith("legacy.txt")) return response(200, log);
    throw new Error(`unexpected URL ${url}`);
  };
  return { fetchImpl, keyId };
}

const base = {
  owner: "trustphoneapp",
  repository: "keyless-cutover",
  runId: "9001",
  installationToken: "github-installation-token-value",
  scopeOwnerId: "1",
  scopeRepositoryId: "2",
};

test("legacy collector binds a fresh online Google key rejection to the scoped run and key", async () => {
  const { fetchImpl, keyId } = fixture();
  const result = await collectFreshLegacyDenialEvidence({ ...base, keyId, fetchImpl });
  assert.equal(result.googleAuthResult.key_id, keyId);
  assert.equal(result.googleAuthResult.outcome, "DENIED");
  assert.equal(result.googleAuthResult.fresh_online_request, true);
  assert.match(result.googleAuthResult.log_sha256, /^[a-f0-9]{64}$/);
});

test("legacy collector refuses a generic network failure", async () => {
  const { fetchImpl, keyId } = fixture("network timeout");
  await assert.rejects(collectFreshLegacyDenialEvidence({ ...base, keyId, fetchImpl }), /does not prove/);
});
