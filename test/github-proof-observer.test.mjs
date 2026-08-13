import assert from "node:assert/strict";
import test from "node:test";

import { fetchGitHubProofObservation } from "../src/github-proof-observer.mjs";

const installationToken = `ghs_${"t".repeat(36)}`;

const workflow = `name: K0 deploy
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
`;
const run = {
  id: 456789123,
  run_attempt: 2,
  status: "completed",
  conclusion: "success",
  path: ".github/workflows/k0-deploy.yml",
  head_sha: "b".repeat(40),
  head_branch: "main",
  event: "workflow_dispatch",
  actor: { id: 111, login: "operator" },
  triggering_actor: { id: 111, login: "operator" },
  repository: {
    id: 222,
    full_name: "trustphoneapp/keyless-cutover",
    owner: { id: 333, login: "trustphoneapp" },
  },
};

function fetchFixture({ approved = true, path = run.path } = {}) {
  return async (url) => {
    let value;
    if (url.includes("/contents/")) {
      value = { encoding: "base64", content: Buffer.from(workflow).toString("base64"), sha: "a".repeat(40) };
    } else if (url.endsWith("/approvals")) {
      value = approved ? [{ state: "approved", user: { id: 444 }, environments: [{ name: "production" }] }] : [];
    } else {
      value = { ...run, path };
    }
    return { ok: true, status: 200, text: async () => JSON.stringify(value) };
  };
}

const input = {
  owner: "trustphoneapp",
  repository: "keyless-cutover",
  runId: "456789123",
  workflowPath: ".github/workflows/k0-deploy.yml",
  environment: "production",
  token: installationToken,
};

test("GitHub observer rebuilds proof context from completed run, blob, and independent review", async () => {
  const observed = await fetchGitHubProofObservation({ ...input, fetchImpl: fetchFixture() });
  assert.deepEqual(observed, {
    owner_id: "333",
    repository_id: "222",
    workflow_path: ".github/workflows/k0-deploy.yml",
    workflow_ref: "trustphoneapp/keyless-cutover/.github/workflows/k0-deploy.yml@refs/heads/main",
    workflow_blob_sha: "a".repeat(40),
    head_sha: "b".repeat(40),
    run_id: "456789123",
    run_attempt: "2",
    actor_id: "111",
    triggering_actor: "operator",
    event_name: "workflow_dispatch",
    ref: "refs/heads/main",
    environment: "production",
    runner_environment: "github-hosted",
  });
});

test("GitHub observer fails closed on wrong workflow or self-approval", async () => {
  await assert.rejects(
    fetchGitHubProofObservation({ ...input, fetchImpl: fetchFixture({ path: ".github/workflows/other.yml" }) }),
    /workflow path/,
  );
  await assert.rejects(
    fetchGitHubProofObservation({ ...input, fetchImpl: fetchFixture({ approved: false }) }),
    /approval/,
  );
});
