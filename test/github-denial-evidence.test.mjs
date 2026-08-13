import assert from "node:assert/strict";
import test from "node:test";
import AdmZip from "adm-zip";

import { collectGitHubDenialEvidence } from "../src/github-denial-evidence.mjs";

const installationToken = `ghs_${"t".repeat(36)}`;

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

function h2Fixture() {
  const run = {
    id: 8002, run_attempt: 1, status: "completed", conclusion: "success", head_sha: "b".repeat(40),
    head_branch: "main", path: ".github/workflows/k0-external-hostile.yml", event: "push",
    repository: { id: 22, full_name: "trustphoneapp/keyless-hostile", owner: { id: 1 } },
  };
  const denial = {
    version: 1, id: "H2", outcome: "failure", run_id: "8002", run_attempt: "1", head_sha: "b".repeat(40),
    workflow_ref: "trustphoneapp/keyless-hostile/.github/workflows/k0-external-hostile.yml@refs/heads/main",
    event: "push", ref: "refs/heads/main", environment: "production", owner_id: "1", repository_id: "22",
  };
  const zip = new AdmZip();
  zip.addFile("k0-external.json", Buffer.from(JSON.stringify(denial)));
  const log = "google-github-actions/auth failed: credential is rejected by the attribute condition at STS";
  const fetchImpl = async (url) => {
    if (url.endsWith("/actions/runs/8002")) return response(200, run);
    if (url.includes("/jobs?")) return response(200, { jobs: [{
      id: 82, name: "external-identity", status: "completed", conclusion: "success",
      steps: [{ name: "Require external identity denial", conclusion: "success" }],
    }] });
    if (url.includes("/artifacts?")) return response(200, { artifacts: [{ id: 92, name: "keyless-external-denial", expired: false }] });
    if (url.endsWith("/actions/artifacts/92/zip")) return response(302, "", { location: "https://objects.githubusercontent.com/h2.zip" });
    if (url.endsWith("/actions/jobs/82/logs")) return response(302, "", { location: "https://objects.githubusercontent.com/h2.txt" });
    if (url.endsWith("h2.zip")) return response(200, zip.toBuffer(), { "content-length": String(zip.toBuffer().length) });
    if (url.endsWith("h2.txt")) return response(200, log, { "content-length": String(log.length) });
    throw new Error(`unexpected URL ${url}`);
  };
  return fetchImpl;
}

const input = {
  owner: "trustphoneapp", repository: "keyless-cutover", runId: "7007", hostileId: "H7",
  installationToken, scopeOwnerId: "1", scopeRepositoryId: "2",
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

test("GitHub collector proves H2 from the intended owner and a different repository ID", async () => {
  const result = await collectGitHubDenialEvidence({
    ...input,
    repository: "keyless-hostile",
    runId: "8002",
    hostileId: "H2",
    scopeRepositoryId: "2",
    fetchImpl: h2Fixture(),
  });
  assert.equal(result.githubRun.owner_id, "1");
  assert.equal(result.githubRun.repository_id, "22");
  assert.equal(result.clientResult.hostile_id, "H2");
  assert.equal(result.clientResult.error_category, "WIF_CONDITION_DENIED");
});
