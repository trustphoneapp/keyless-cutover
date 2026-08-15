import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import AdmZip from "adm-zip";

import { collectFreshLegacyDenialEvidence, collectSuccessfulLegacyDeploy } from "../src/github-legacy-evidence.mjs";
import { assembleK0Bundle } from "../src/k0-bundle.mjs";
import {
  evidenceByKind,
  refreshCheckpointReceipt,
  refreshFinalCredentialScan,
  validK0BundleInput,
} from "./fixtures/k0-bundle.mjs";

const installationToken = `ghs_${"t".repeat(36)}`;
const legacyTemplate = await readFile(new URL("../k0/templates/k0-deploy.legacy.yml", import.meta.url));

function response(status, value, extraHeaders = {}) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
  return new Response(bytes, {
    status,
    headers: { date: "Thu, 13 Aug 2026 12:10:00 GMT", ...extraHeaders },
  });
}

function fixture(options = {}) {
  const {
    log = "gcloud: problem refreshing auth tokens: invalid_grant: Invalid JWT Signature",
    mutateRun,
    mutateJobs,
    mutateArtifacts,
  } = typeof options === "string" ? { log: options } : options;
  const keyId = "a".repeat(40);
  const workflow = "name: legacy probe\n";
  const run = {
    id: 9001, run_attempt: 1, status: "completed", conclusion: "success", head_sha: "b".repeat(40),
    head_branch: "main", path: ".github/workflows/k0-legacy-auth-check.yml", event: "workflow_dispatch",
    run_started_at: "2026-08-13T12:02:00.123456789Z", actor: { id: 10 },
    repository: { id: 2, full_name: "trustphoneapp/keyless-cutover", owner: { id: 1 } },
  };
  const artifact = {
    version: 1, id: "legacy-after-disable", outcome: "failure", key_id: keyId, run_id: "9001", run_attempt: "1",
    head_sha: "b".repeat(40), workflow_ref: "trustphoneapp/keyless-cutover/.github/workflows/k0-legacy-auth-check.yml@refs/heads/main",
    event: "workflow_dispatch", ref: "refs/heads/main", environment: "production", fresh_runner: true, fresh_online_request: true,
  };
  const zip = new AdmZip();
  zip.addFile("k0-legacy-after-disable.json", Buffer.from(JSON.stringify(artifact)));
  const jobsResponse = { total_count: 1, jobs: [{
    id: 91, name: "fresh-legacy-auth", status: "completed", conclusion: "success",
    runner_group_name: "GitHub Actions", labels: ["ubuntu-latest"],
    started_at: "2026-08-13T12:02:30.123456789Z",
    completed_at: "2026-08-13T12:03:00.123456789Z",
    steps: [{ name: "Require fresh legacy denial", conclusion: "success" }],
  }] };
  const artifactsResponse = {
    total_count: 1,
    artifacts: [{ id: 92, name: "keyless-legacy-after-disable", expired: false }],
  };
  mutateRun?.(run);
  mutateJobs?.(jobsResponse);
  mutateArtifacts?.(artifactsResponse);
  const fetchImpl = async (url) => {
    if (url.endsWith("/actions/runs/9001")) return response(200, run);
    if (url.includes("/jobs?")) return response(200, jobsResponse);
    if (url.includes("/artifacts?")) return response(200, artifactsResponse);
    if (url.endsWith("/actions/artifacts/92/zip")) return response(302, "", { location: "https://objects.githubusercontent.com/legacy.zip" });
    if (url.endsWith("/actions/jobs/91/logs")) return response(302, "", { location: "https://objects.githubusercontent.com/legacy.txt" });
    if (url.endsWith("legacy.zip")) return response(200, zip.toBuffer());
    if (url.endsWith("legacy.txt")) return response(200, log);
    if (url.includes("/contents/")) return response(200, { encoding: "base64", content: Buffer.from(workflow).toString("base64"), sha: "c".repeat(40) });
    throw new Error(`unexpected URL ${url}`);
  };
  return { fetchImpl, keyId };
}

const base = {
  owner: "trustphoneapp",
  repository: "keyless-cutover",
  runId: "9001",
  installationToken,
  scopeOwnerId: "1",
  scopeRepositoryId: "2",
};

function baselineFixture({ mutate = () => {}, headers = { date: "Thu, 13 Aug 2026 12:18:00 GMT" } } = {}) {
  const headSha = "d".repeat(40);
  const pullHead = "0".repeat(40);
  const values = {
    run: {
      id: 8001, run_attempt: 1, status: "completed", conclusion: "success", head_sha: headSha,
      head_branch: "main", path: ".github/workflows/k0-deploy.yml", event: "workflow_dispatch",
      run_started_at: "2026-08-13T10:46:00Z", updated_at: "2026-08-13T10:48:00Z", actor: { id: 10 },
      repository: { id: 2, full_name: "trustphoneapp/keyless-cutover", owner: { id: 1 } },
    },
    jobs: { total_count: 1, jobs: [{
      id: 81, name: "deploy", status: "completed", conclusion: "success",
      runner_group_name: "GitHub Actions", labels: ["ubuntu-latest"],
      started_at: "2026-08-13T10:46:05Z", completed_at: "2026-08-13T10:47:30Z",
      steps: [
        { name: "Read the reviewed release marker", conclusion: "success" },
        { name: "Authenticate with the legacy key", conclusion: "success" },
        { name: "Deploy through the legacy key", conclusion: "success" },
      ],
    }] },
    environmentApprovals: [{ state: "approved", user: { id: 11 }, environments: [{ name: "production" }] }],
    pull: {
      number: 5, state: "closed", merged: true, merged_at: "2026-08-13T10:44:00Z",
      merge_commit_sha: "a".repeat(40), head: { sha: pullHead }, user: { id: 20 },
      base: { ref: "main", repo: { id: 2, full_name: "trustphoneapp/keyless-cutover", owner: { id: 1 } } },
    },
    reviews: [{ state: "APPROVED", commit_id: pullHead, submitted_at: "2026-08-13T10:43:00Z", user: { id: 21 } }],
    protection: {
      required_status_checks: { strict: true, checks: [{ context: "test", app_id: 15368 }] },
      required_pull_request_reviews: {
        required_approving_review_count: 1, dismiss_stale_reviews: true, require_last_push_approval: true,
      },
      enforce_admins: { enabled: true },
    },
    reviewedContent: {
      encoding: "base64", content: legacyTemplate.toString("base64"),
      sha: "62ec226833a2ac44913044ab665a01b0f0f271db",
    },
    runContent: {
      encoding: "base64", content: legacyTemplate.toString("base64"),
      sha: "62ec226833a2ac44913044ab665a01b0f0f271db",
    },
    release: { encoding: "base64", content: Buffer.from("legacy-1\n").toString("base64"), sha: "f812d757b68999535b363515a96b4ec8e6462e9d" },
  };
  mutate(values);
  const reply = (value) => {
    const body = typeof value === "string" ? value : JSON.stringify(value);
    return new Response(body, {
      status: 200,
      headers: {
        ...headers,
        "content-length": String(Buffer.byteLength(body)),
      },
    });
  };
  return async (url) => {
    if (url.endsWith("/actions/runs/8001")) return reply(values.run);
    if (url.includes("/actions/runs/8001/jobs")) return reply(values.jobs);
    if (url.endsWith("/actions/runs/8001/approvals")) return reply(values.environmentApprovals);
    if (url.endsWith("/pulls/5")) return reply(values.pull);
    if (url.includes("/pulls/5/reviews")) return reply(values.reviews);
    if (url.endsWith("/branches/main/protection")) return reply(values.protection);
    if (url.includes(`/contents/.github/workflows/k0-deploy.yml?ref=${pullHead}`)) return reply(values.reviewedContent);
    if (url.includes(`/contents/.github/workflows/k0-deploy.yml?ref=${headSha}`)) return reply(values.runContent);
    if (url.includes("/contents/demo/release.txt")) return reply(values.release);
    throw new Error(`unexpected URL ${url}`);
  };
}

const baseline = {
  owner: "trustphoneapp",
  repository: "keyless-cutover",
  runId: "8001",
  pullNumber: 5,
  installationToken,
};

test("legacy collector binds a fresh online Google key rejection to the scoped run and key", async () => {
  const { fetchImpl, keyId } = fixture();
  const result = await collectFreshLegacyDenialEvidence({ ...base, keyId, fetchImpl });
  assert.equal(result.googleAuthResult.key_id, keyId);
  assert.equal(result.googleAuthResult.outcome, "DENIED");
  assert.equal(result.googleAuthResult.fresh_online_request, true);
  assert.equal(result.googleAuthResult.run_attempt, "1");
  assert.equal(result.googleAuthResult.reached_google, true);
  assert.equal(result.googleAuthResult.rejected_at, "2026-08-13T12:03:00.123456789Z");
  assert.equal(result.observedAt, "2026-08-13T12:10:00Z");
  assert.match(result.githubRun.workflow_sha256, /^[a-f0-9]{64}$/);
  assert.match(result.googleAuthResult.log_sha256, /^[a-f0-9]{64}$/);
});

test("legacy collector refuses a generic network failure", async () => {
  const { fetchImpl, keyId } = fixture("network timeout");
  await assert.rejects(collectFreshLegacyDenialEvidence({ ...base, keyId, fetchImpl }), /does not prove/);
});

test("legacy collector rejects authenticated observations before the completed job", async () => {
  const { fetchImpl, keyId } = fixture();
  await assert.rejects(() => collectFreshLegacyDenialEvidence({
    ...base,
    keyId,
    fetchImpl: async (url, options) => {
      const original = await fetchImpl(url, options);
      if (!url.includes("/contents/")) return original;
      return new Response(await original.arrayBuffer(), {
        status: original.status,
        headers: { date: "Thu, 13 Aug 2026 12:03:00 GMT" },
      });
    },
  }), /after collection/);
});

test("legacy collector rejects run and job events outside the authoritative timeline", async () => {
  const attacks = [
    { mutateRun: (run) => { run.run_started_at = "2026-08-13T12:04:00Z"; } },
    { mutateJobs: (page) => { page.jobs[0].started_at = "2026-08-13T12:01:00Z"; } },
    { mutateJobs: (page) => { page.jobs[0].started_at = "2026-08-13T12:04:00Z"; } },
    { mutateJobs: (page) => { page.jobs[0].completed_at = "2026-08-13T12:01:00Z"; } },
    { mutateJobs: (page) => { delete page.jobs[0].started_at; } },
  ];
  for (const options of attacks) {
    const { fetchImpl, keyId } = fixture(options);
    await assert.rejects(() => collectFreshLegacyDenialEvidence({ ...base, keyId, fetchImpl }), /timeline/);
  }
});

test("legacy collector requires authoritative GitHub-hosted runner metadata", async () => {
  for (const mutateJobs of [
    (page) => { page.jobs[0].runner_group_name = "Self-hosted"; },
    (page) => { page.jobs[0].labels = ["linux", "x64"]; },
  ]) {
    const { fetchImpl, keyId } = fixture({ mutateJobs });
    await assert.rejects(collectFreshLegacyDenialEvidence({ ...base, keyId, fetchImpl }), /legacy denial assertion/);
  }
});

test("legacy collector rejects incomplete or ambiguous bounded job and artifact pages", async () => {
  const pages = ["Jobs", "Artifacts"];
  const mutations = [
    (page) => { delete page.total_count; },
    (page) => { page.total_count = 0; },
    (page) => { page.total_count = 2; },
    (page) => {
      const field = page.jobs ? "jobs" : "artifacts";
      page[field].push(...Array.from({ length: 100 }, (_, index) => ({ id: 2_000 + index, name: `other-${index}` })));
      page.total_count = 101;
    },
    (page) => {
      const field = page.jobs ? "jobs" : "artifacts";
      page[field].push({ ...page[field][0], id: page[field][0].id + 1 });
      page.total_count = 2;
    },
  ];
  for (const pageName of pages) {
    for (const mutation of mutations) {
      const option = `mutate${pageName}`;
      const { fetchImpl, keyId } = fixture({ [option]: mutation });
      await assert.rejects(collectFreshLegacyDenialEvidence({ ...base, keyId, fetchImpl }));
    }
  }
});

test("legacy baseline collector accepts only the reviewed inactive workflow fixture", async () => {
  const result = await collectSuccessfulLegacyDeploy({ ...baseline, fetchImpl: baselineFixture() });
  assert.equal(result.githubRun.event, "workflow_dispatch");
  assert.equal(result.observedAt, "2026-08-13T12:18:00Z");
  assert.equal(result.githubRun.release_marker, "legacy-1");
  assert.equal(result.githubRun.workflow_sha256, "efa494890963b2744b031a54f78f13df5575b948eec9fa2ec452342fda6feebf");
  assert.equal(result.workflowApproval.workflow_sha256, result.githubRun.workflow_sha256);
  assert.equal(result.environmentReview.reviewer_id, "11");
  const text = legacyTemplate.toString("utf8");
  assert.match(text, /workflow_dispatch:/);
  assert.match(text, /github\.ref == 'refs\/heads\/main'/);
  assert.match(text, /credentials_json: \$\{\{ secrets\.GCP_SERVICE_ACCOUNT_KEY \}\}/);
  assert.doesNotMatch(text, /id-token|GCP_WIF_PROVIDER|GCP_FORBIDDEN_SERVICE/);

  const input = validK0BundleInput();
  input.manifest.legacy_baseline.run_id = result.githubRun.run_id;
  input.manifest.legacy_baseline.run_attempt = result.githubRun.run_attempt;
  input.manifest.legacy_baseline.head_sha = result.githubRun.head_sha;
  const approval = evidenceByKind(input, "GITHUB_PULL_REQUEST", "baseline-workflow-approval");
  const run = evidenceByKind(input, "GITHUB_RUN", "legacy-baseline");
  const review = evidenceByKind(input, "GITHUB_ENVIRONMENT_REVIEW", "legacy-baseline-review");
  approval.data = result.workflowApproval;
  run.data = result.githubRun;
  review.data = result.environmentReview;
  approval.observed_at = result.observedAt;
  run.observed_at = result.observedAt;
  review.observed_at = result.observedAt;
  refreshCheckpointReceipt(input);
  refreshFinalCredentialScan(input);
  await assembleK0Bundle(input);
});

test("legacy baseline collector refuses duplicate JSON keys", async () => {
  const fetchImpl = async (url) => {
    if (url.includes("/repos/") && !url.includes("/contents/") && !url.includes("/actions/") && !url.includes("/pulls")) {
      const body = '{"id":1,"id":2}';
      return new Response(body, {
        status: 200,
        headers: {
          date: "Thu, 13 Aug 2026 12:18:00 GMT",
          "content-length": String(Buffer.byteLength(body)),
        },
      });
    }
    return baselineFixture()(url);
  };
  await assert.rejects(() => collectSuccessfulLegacyDeploy({ ...baseline, fetchImpl }), /duplicate JSON key/);
});

test("legacy baseline collector rejects unreviewed, unbounded, or noncanonical success claims", async () => {
  const attacks = [
    ["self environment review", (value) => { value.environmentApprovals[0].user.id = 10; }],
    ["self pull review", (value) => { value.reviews[0].user.id = 20; }],
    ["wrong trigger", (value) => { value.run.event = "push"; }],
    ["wrong workflow", (value) => { value.runContent.content = Buffer.from("name: wrong\n").toString("base64"); }],
    ["failed auth", (value) => { value.jobs.jobs[0].steps[1].conclusion = "failure"; }],
    ["missing job total", (value) => { delete value.jobs.total_count; }],
    ["unbounded approvals", (value) => {
      value.environmentApprovals = Array.from({ length: 100 }, () => value.environmentApprovals[0]);
    }],
    ["unbounded reviews", (value) => { value.reviews = Array.from({ length: 100 }, () => value.reviews[0]); }],
    ["weak protection", (value) => { value.protection.required_status_checks.strict = false; }],
  ];
  for (const [label, mutate] of attacks) {
    await assert.rejects(() => collectSuccessfulLegacyDeploy({
      ...baseline,
      fetchImpl: baselineFixture({ mutate }),
    }), undefined, label);
  }
  await assert.rejects(() => collectSuccessfulLegacyDeploy({
    ...baseline,
    fetchImpl: baselineFixture({ headers: {} }),
  }), /authoritative time/);
  await assert.rejects(() => collectSuccessfulLegacyDeploy({
    ...baseline,
    fetchImpl: baselineFixture({ headers: { date: "Thu, 13 Aug 2026 10:42:00 GMT" } }),
  }), /after collection/);
  await assert.rejects(() => collectSuccessfulLegacyDeploy({
    ...baseline,
    fetchImpl: baselineFixture({ headers: {
      date: "Thu, 13 Aug 2026 12:18:00 GMT",
      link: "<https://api.github.com/page=2>; rel=\"next\"",
    } }),
  }), /unbounded/);
});
