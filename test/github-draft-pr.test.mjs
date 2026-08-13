import assert from "node:assert/strict";
import test from "node:test";

import { openDraftCutoverPr } from "../src/github-draft-pr.mjs";
import { buildCutoverPlan } from "../src/workflow-cutover.mjs";
import { readFile } from "node:fs/promises";

const current = await readFile(new URL("../k0/fixtures/k0-deploy.legacy.yml", import.meta.url), "utf8");
const replacement = await readFile(new URL("../k0/templates/k0-deploy.wif.yml", import.meta.url), "utf8");
const plan = buildCutoverPlan(current, replacement);
const baseSha = "a".repeat(40);
const blobSha = "b".repeat(40);
const installationToken = `ghs_${"t".repeat(36)}`;

function response(status, value) {
  return { status, text: async () => JSON.stringify(value) };
}

function createFetch({ repositoryId = 2, existing = false, existingBranch = false } = {}) {
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, method: options.method, body: options.body && JSON.parse(options.body) });
    if (url.endsWith("/repos/trustphoneapp/keyless-cutover")) return response(200, {
      id: repositoryId,
      owner: { id: 1 },
      default_branch: "main",
      full_name: "trustphoneapp/keyless-cutover",
    });
    if (url.endsWith("/git/ref/heads/main")) return response(200, { object: { type: "commit", sha: baseSha } });
    if (url.includes("/git/ref/heads%2Fkeyless%2Fk0")) return existingBranch
      ? response(200, { object: { type: "commit", sha: "c".repeat(40) } })
      : response(404, { message: "Not Found" });
    if (url.includes("?ref=keyless%2Fk0")) return response(200, {
      encoding: "base64", content: Buffer.from(replacement).toString("base64"), sha: "d".repeat(40),
    });
    if (url.includes("/contents/.github/workflows/k0-deploy.yml?ref=")) return response(200, {
      encoding: "base64", content: Buffer.from(current).toString("base64"), sha: blobSha,
    });
    if (url.includes("/pulls?state=open")) return response(200, existing ? [{
      number: 7,
      draft: true,
      html_url: "https://github.com/trustphoneapp/keyless-cutover/pull/7",
      body: `<!-- keyless-migration:k0 plan:${plan.plan_digest} -->`,
    }] : []);
    if (url.endsWith("/git/refs")) return response(201, { ref: "refs/heads/keyless/k0" });
    if (url.endsWith("/contents/.github/workflows/k0-deploy.yml")) return response(200, { commit: { sha: "c".repeat(40) } });
    if (url.endsWith("/pulls")) return response(201, { number: 7, draft: true, html_url: "https://github.com/trustphoneapp/keyless-cutover/pull/7" });
    throw new Error(`unexpected request ${options.method} ${url}`);
  };
  return { fetchImpl, requests };
}

const input = {
  owner: "trustphoneapp",
  repository: "keyless-cutover",
  installationToken,
  migrationId: "k0",
  approvedOwnerId: "1",
  approvedRepositoryId: "2",
  approvedBaseSha: baseSha,
  approvedCutoverPlan: plan,
  replacementWorkflow: replacement,
};

test("GitHub adapter opens one draft PR from exact compiler bytes", async () => {
  const { fetchImpl, requests } = createFetch();
  assert.deepEqual(await openDraftCutoverPr({ ...input, fetchImpl }), {
    number: 7,
    url: "https://github.com/trustphoneapp/keyless-cutover/pull/7",
    commit_sha: "c".repeat(40),
    reused: false,
  });
  const contentWrite = requests.find(({ method, url }) => method === "PUT" && url.endsWith("k0-deploy.yml"));
  assert.equal(Buffer.from(contentWrite.body.content, "base64").toString("utf8"), replacement);
  assert.equal(requests.some(({ url }) => /merge/.test(url)), false);
  assert.equal(JSON.stringify(requests).includes(input.installationToken), false);
});

test("GitHub adapter refuses repository identity drift before mutation", async () => {
  const { fetchImpl, requests } = createFetch({ repositoryId: 999 });
  await assert.rejects(openDraftCutoverPr({ ...input, fetchImpl }), /repository identity/);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, "GET");
});

test("GitHub adapter reuses only an exact existing draft PR", async () => {
  const { fetchImpl, requests } = createFetch({ existing: true });
  assert.deepEqual(await openDraftCutoverPr({ ...input, fetchImpl }), {
    number: 7,
    url: "https://github.com/trustphoneapp/keyless-cutover/pull/7",
    reused: true,
  });
  assert.equal(requests.every(({ method }) => method === "GET"), true);
});

test("GitHub adapter recovers an exact branch left before PR creation", async () => {
  const { fetchImpl, requests } = createFetch({ existingBranch: true });
  const result = await openDraftCutoverPr({ ...input, fetchImpl });
  assert.equal(result.commit_sha, "c".repeat(40));
  assert.equal(result.reused, false);
  assert.equal(requests.some(({ method }) => method === "PUT"), false);
  assert.equal(requests.filter(({ method }) => method === "POST").length, 1);
});
