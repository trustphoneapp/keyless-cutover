import assert from "node:assert/strict";
import test from "node:test";
import AdmZip from "adm-zip";

import { collectGitHubDenialEvidence } from "../src/github-denial-evidence.mjs";

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

function fixture(log = "google-github-actions/auth failed: audience rejected by Security Token Service") {
  const run = {
    id: 7007, run_attempt: 1, status: "completed", conclusion: "success", head_sha: "a".repeat(40),
    head_branch: "main", path: ".github/workflows/k0-deploy.yml", event: "push",
    repository: { id: 2, full_name: "trustphoneapp/keyless-cutover", owner: { id: 1 } },
  };
  const denial = {
    version: 1, id: "H7", outcome: "failure", run_id: "7007", run_attempt: "1", head_sha: "a".repeat(40),
    workflow_ref: "trustphoneapp/keyless-cutover/.github/workflows/k0-deploy.yml@refs/heads/main",
    event: "push", ref: "refs/heads/main", environment: "production",
    audience: "https://iam.googleapis.com/projects/0/locations/global/workloadIdentityPools/wrong/providers/wrong",
  };
  const zip = new AdmZip();
  zip.addFile("k0-H7.json", Buffer.from(JSON.stringify(denial)));
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, authorization: options.headers?.authorization });
    if (url.endsWith("/actions/runs/7007")) return response(200, run);
    if (url.includes("/jobs?")) return response(200, { jobs: [{
      id: 77, name: "h7-wrong-audience", status: "completed", conclusion: "success",
      steps: [{ name: "Require H7 denial", conclusion: "success" }],
    }] });
    if (url.includes("/artifacts?")) return response(200, { artifacts: [{ id: 88, name: "keyless-h7-denial", expired: false }] });
    if (url.endsWith("/actions/artifacts/88/zip")) return response(302, "", { location: "https://objects.githubusercontent.com/artifact.zip" });
    if (url.endsWith("/actions/jobs/77/logs")) return response(302, "", { location: "https://objects.githubusercontent.com/job.txt" });
    if (url.endsWith("artifact.zip")) return response(200, zip.toBuffer(), { "content-length": String(zip.toBuffer().length) });
    if (url.endsWith("job.txt")) return response(200, log, { "content-length": String(log.length) });
    throw new Error(`unexpected URL ${url}`);
  };
  return { fetchImpl, requests };
}

const input = {
  owner: "trustphoneapp", repository: "keyless-cutover", runId: "7007", hostileId: "H7",
  installationToken: "github-installation-token-value", scopeOwnerId: "1", scopeRepositoryId: "2",
  forbiddenService: "keyless-forbidden",
};

test("GitHub collector proves a hostile denial from API, artifact, and allowlisted log signature", async () => {
  const { fetchImpl, requests } = fixture();
  const result = await collectGitHubDenialEvidence({ ...input, fetchImpl });
  assert.equal(result.githubRun.run_id, "7007");
  assert.equal(result.githubRun.environment, "production");
  assert.equal(result.clientResult.hostile_id, "H7");
  assert.equal(result.clientResult.error_category, "AUDIENCE_DENIED");
  assert.equal(result.clientResult.reached_sts, true);
  assert.match(result.clientResult.log_sha256, /^[a-f0-9]{64}$/);
  assert.equal(requests.filter(({ url }) => url.startsWith("https://objects.githubusercontent.com"))
    .every(({ authorization }) => authorization === undefined), true);
});

test("GitHub collector refuses a generic failure before the intended control", async () => {
  const { fetchImpl } = fixture("network timeout before authentication");
  await assert.rejects(collectGitHubDenialEvidence({ ...input, fetchImpl }), /does not prove/);
});
