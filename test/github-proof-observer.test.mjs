import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { fetchGitHubProofObservation } from "../src/github-proof-observer.mjs";

const installationToken = `ghs_${"t".repeat(36)}`;

const workflow = `name: K0 deploy
jobs:
  proof:
    runs-on: ubuntu-latest
    environment: production
`;
const run = {
  id: 456789123,
  run_attempt: 2,
  status: "completed",
  conclusion: "success",
  path: ".github/workflows/k0-proof-v2.yml",
  head_sha: "b".repeat(40),
  head_branch: "main",
  run_started_at: "2026-08-13T12:00:00.123456789Z",
  event: "workflow_dispatch",
  actor: { id: 111, login: "operator" },
  triggering_actor: { id: 111, login: "operator" },
  repository: {
    id: 222,
    full_name: "trustphoneapp/keyless-cutover",
    owner: { id: 333, login: "trustphoneapp" },
  },
};

function fetchFixture({ approved = true, path = run.path, reviewerId = 444, mutateJobs } = {}) {
  const jobsResponse = { total_count: 1, jobs: [{
    id: 555,
    name: "proof",
    status: "completed",
    conclusion: "success",
    started_at: "2026-08-13T12:00:01.123456789Z",
    completed_at: "2026-08-13T12:01:00Z",
    runner_group_name: "GitHub Actions",
    labels: ["ubuntu-latest"],
  }] };
  mutateJobs?.(jobsResponse);
  return async (url) => {
    let value;
    if (url.includes("/contents/")) {
      value = { encoding: "base64", content: Buffer.from(workflow).toString("base64"), sha: "a".repeat(40) };
    } else if (url.endsWith("/approvals")) {
      value = approved ? [{ state: "approved", user: { id: reviewerId, login: "reviewer" }, environments: [{ name: "production" }] }] : [];
    } else if (url.includes("/jobs?")) {
      value = jobsResponse;
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
  workflowPath: ".github/workflows/k0-proof-v2.yml",
  environment: "production",
  token: installationToken,
};

test("GitHub observer rebuilds proof context from completed run, blob, and independent review", async () => {
  const observed = await fetchGitHubProofObservation({ ...input, fetchImpl: fetchFixture() });
  assert.deepEqual(observed, {
    owner_id: "333",
    repository_id: "222",
    workflow_path: ".github/workflows/k0-proof-v2.yml",
    workflow_ref: "trustphoneapp/keyless-cutover/.github/workflows/k0-proof-v2.yml@refs/heads/main",
    workflow_blob_sha: "a".repeat(40),
    workflow_sha256: createHash("sha256").update(workflow).digest("hex"),
    head_sha: "b".repeat(40),
    run_id: "456789123",
    run_attempt: "2",
    actor_id: "111",
    triggering_actor: "operator",
    event_name: "workflow_dispatch",
    ref: "refs/heads/main",
    environment: "production",
    runner_environment: "github-hosted",
    started_at: run.run_started_at,
    release_marker: null,
    environment_review: {
      state: "approved",
      environment: "production",
      reviewer_id: "444",
      reviewer_login: "reviewer",
    },
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
  await assert.rejects(
    fetchGitHubProofObservation({ ...input, fetchImpl: fetchFixture({ reviewerId: run.actor.id }) }),
    /approval/,
  );
});

test("GitHub observer requires one bounded authoritative GitHub-hosted ProofV2 job", async () => {
  const mutations = [
    (page) => { page.jobs[0].runner_group_name = "Self-hosted"; },
    (page) => { page.jobs[0].labels = ["linux", "x64"]; },
    (page) => { page.total_count = 2; },
  ];
  for (const mutateJobs of mutations) {
    await assert.rejects(fetchGitHubProofObservation({
      ...input,
      fetchImpl: fetchFixture({ mutateJobs }),
    }));
  }
});

test("GitHub observer refuses push events and duplicate JSON keys", async () => {
  await assert.rejects(fetchGitHubProofObservation({
    ...input,
    fetchImpl: async (url) => {
      if (url.includes("/actions/runs/") && !url.includes("/jobs") && !url.includes("/approvals")) {
        return { ok: true, status: 200, text: async () => JSON.stringify({ ...run, event: "push" }) };
      }
      return fetchFixture()(url);
    },
  }), /event_name/);
  await assert.rejects(fetchGitHubProofObservation({
    ...input,
    fetchImpl: async (url) => {
      if (url.includes("/actions/runs/") && !url.includes("/jobs") && !url.includes("/approvals")) {
        return {
          ok: true,
          status: 200,
          text: async () => '{"id":456789123,"id":456789123,"event":"workflow_dispatch"}',
        };
      }
      return fetchFixture()(url);
    },
  }), /duplicate JSON key/);
  await assert.rejects(fetchGitHubProofObservation({
    ...input,
    fetchImpl: fetchFixture({
      mutateJobs: (page) => { delete page.jobs[0].started_at; },
    }),
  }), /timeline/);
  await assert.rejects(fetchGitHubProofObservation({
    ...input,
    fetchImpl: async (url) => {
      if (url.includes("/actions/runs/") && !url.includes("/jobs") && !url.includes("/approvals")) {
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ ...run, note: `AKIA${"A".repeat(16)}` }),
        };
      }
      return fetchFixture()(url);
    },
  }), /credential-shaped/);
});
