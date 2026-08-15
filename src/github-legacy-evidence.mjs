import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import {
  boundedGitHubPage,
  downloadGitHubBytes,
  downloadGitHubBytesObserved,
  extractSingleJsonArtifact,
  fetchGitHubJson,
  fetchGitHubJsonObserved,
  isGitHubHostedJob,
} from "./github-denial-evidence.mjs";
import { requireGitHubInstallationToken } from "./github-token.mjs";
import { githubReleaseMarker, githubWorkflowSnapshot } from "./github-workflow-snapshot.mjs";
import { rejectDuplicateJsonKeys } from "./observation-time.mjs";
import { isRfc3339, timestampAtOrBefore, timestampBefore, timestampNanoseconds } from "./rfc3339.mjs";

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}$/;
const NUMERIC = /^\d+$/;
const KEY_ID = /^[a-f0-9]{40}$/;
const SHA = /^[a-f0-9]{40}$/;
const BASELINE_WORKFLOW = ".github/workflows/k0-deploy.yml";
const BASELINE_TEMPLATE = new URL("../k0/templates/k0-deploy.legacy.yml", import.meta.url);

function exact(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function provesGoogleKeyRejection(log) {
  const value = log.toString("utf8");
  return /(invalid_grant|Invalid JWT Signature|service account key .* disabled|key has been disabled)/i.test(value)
    && /(gcloud|oauth2|refreshing .* auth|google-github-actions\/auth)/i.test(value);
}

async function fetchBaselineJson(url, token, fetchImpl) {
  const response = await fetchImpl(url, {
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${token}`,
      "x-github-api-version": "2022-11-28",
    },
    redirect: "error",
    signal: AbortSignal.timeout(8_000),
  });
  const date = response?.headers?.get?.("date");
  const milliseconds = typeof date === "string" ? Date.parse(date) : NaN;
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toUTCString() !== date
      || /rel="next"/.test(response?.headers?.get?.("link") ?? "")) {
    throw new Error("legacy baseline GitHub response is unbounded or has no authoritative time");
  }
  const text = await response.text();
  if (text.length > 1_000_000) throw new Error("GitHub API response is too large");
  if (!response.ok) throw new Error(`GitHub API failed with HTTP ${response.status}`);
  rejectDuplicateJsonKeys(text);
  return {
    value: JSON.parse(text),
    observedAt: new Date(milliseconds).toISOString().replace(".000Z", "Z"),
  };
}

export async function collectFreshLegacyDenialEvidence({
  owner,
  repository,
  runId,
  installationToken,
  scopeOwnerId,
  scopeRepositoryId,
  keyId,
  fetchImpl = fetch,
}) {
  exact(owner, OWNER, "owner");
  exact(repository, REPOSITORY, "repository");
  exact(String(runId), NUMERIC, "run ID");
  const token = requireGitHubInstallationToken(installationToken);
  const ownerId = exact(scopeOwnerId, NUMERIC, "scope owner ID");
  const repositoryId = exact(scopeRepositoryId, NUMERIC, "scope repository ID");
  exact(keyId, KEY_ID, "key ID");
  const base = `https://api.github.com/repos/${owner}/${repository}`;
  const firstResponses = await Promise.all([
    fetchGitHubJsonObserved(`${base}/actions/runs/${runId}`, token, fetchImpl),
    fetchGitHubJsonObserved(`${base}/actions/runs/${runId}/jobs?per_page=100`, token, fetchImpl),
    fetchGitHubJsonObserved(`${base}/actions/runs/${runId}/artifacts?per_page=100`, token, fetchImpl),
  ]);
  const [run, jobsResponse, artifactsResponse] = firstResponses.map(({ value }) => value);
  if (String(run?.id) !== String(runId) || run?.status !== "completed" || run?.conclusion !== "success"
      || run?.repository?.full_name !== `${owner}/${repository}` || String(run?.repository?.owner?.id) !== ownerId
      || String(run?.repository?.id) !== repositoryId || run?.path !== ".github/workflows/k0-legacy-auth-check.yml"
      || run?.event !== "workflow_dispatch" || run?.head_branch !== "main" || !exact(run?.head_sha, SHA, "head SHA")) {
    throw new Error("fresh legacy run does not match the scoped protected probe");
  }
  const jobs = boundedGitHubPage(jobsResponse, "jobs").filter(({ name }) => name === "fresh-legacy-auth");
  if (jobs.length !== 1 || jobs[0].status !== "completed" || jobs[0].conclusion !== "success"
      || !isGitHubHostedJob(jobs[0])
      || jobs[0].steps?.find(({ name }) => name === "Require fresh legacy denial")?.conclusion !== "success") {
    throw new Error("fresh legacy denial assertion is missing or unsuccessful");
  }
  if (!isRfc3339(run.run_started_at) || !isRfc3339(jobs[0].started_at) || !isRfc3339(jobs[0].completed_at)
      || !timestampAtOrBefore(run.run_started_at, jobs[0].started_at)
      || !timestampAtOrBefore(jobs[0].started_at, jobs[0].completed_at)) {
    throw new Error("fresh legacy timeline is invalid");
  }
  const artifacts = boundedGitHubPage(artifactsResponse, "artifacts")
    .filter((item) => item.name === "keyless-legacy-after-disable" && !item.expired);
  if (artifacts.length !== 1 || !Number.isInteger(artifacts[0].id)) {
    throw new Error("fresh legacy denial artifact is missing or ambiguous");
  }
  const downloadResponses = await Promise.all([
    downloadGitHubBytesObserved(
      `${base}/actions/artifacts/${artifacts[0].id}/zip`, token, fetchImpl, 512_000, jobs[0].completed_at,
    ),
    downloadGitHubBytesObserved(
      `${base}/actions/jobs/${jobs[0].id}/logs`, token, fetchImpl, 1_000_000, jobs[0].completed_at,
    ),
  ]);
  const [zip, log] = downloadResponses.map(({ bytes }) => bytes);
  const value = extractSingleJsonArtifact(zip, "k0-legacy-after-disable.json");
  const allowed = new Set([
    "environment", "event", "fresh_online_request", "fresh_runner", "head_sha", "id", "key_id", "outcome",
    "ref", "run_attempt", "run_id", "version", "workflow_ref",
  ]);
  if (!value || typeof value !== "object" || Object.keys(value).some((field) => !allowed.has(field))
      || value.version !== 1 || value.id !== "legacy-after-disable" || value.outcome !== "failure"
      || value.key_id !== keyId || value.run_id !== String(run.id) || value.run_attempt !== String(run.run_attempt)
      || value.head_sha !== run.head_sha || value.event !== run.event || value.ref !== "refs/heads/main"
      || value.environment !== "production" || value.fresh_runner !== true || value.fresh_online_request !== true
      || value.workflow_ref !== `${owner}/${repository}/${run.path}@refs/heads/main`) {
    throw new Error("fresh legacy denial artifact does not match the run and scoped key");
  }
  if (!provesGoogleKeyRejection(log)) throw new Error("fresh legacy log does not prove a Google key rejection");
  const workflowResponse = await fetchGitHubJsonObserved(
    `${base}/contents/${run.path}?ref=${run.head_sha}`,
    token,
    fetchImpl,
  );
  const workflow = githubWorkflowSnapshot(workflowResponse.value);
  const observations = [...firstResponses, ...downloadResponses, workflowResponse].map(({ observedAt }) => observedAt);
  if (observations.some((value) => !timestampAtOrBefore(jobs[0].completed_at, value))) {
    throw new Error("fresh legacy evidence occurrence is after collection");
  }
  const observedAt = observations.reduce((latest, value) => timestampAtOrBefore(latest, value) ? value : latest);
  return {
    observedAt,
    githubRun: {
      run_id: String(run.id),
      run_attempt: String(run.run_attempt),
      head_sha: run.head_sha,
      workflow_path: run.path,
      workflow_ref: value.workflow_ref,
      owner_id: ownerId,
      repository_id: repositoryId,
      event: run.event,
      ref: value.ref,
      environment: value.environment,
      conclusion: run.conclusion,
      runner_environment: "github-hosted",
      started_at: run.run_started_at,
      release_marker: null,
      workflow_blob_sha: workflow.workflow_blob_sha,
      workflow_sha256: workflow.workflow_sha256,
      actor_id: exact(String(run?.actor?.id), NUMERIC, "run actor ID"),
    },
    googleAuthResult: {
      key_id: keyId,
      run_id: String(run.id),
      run_attempt: String(run.run_attempt),
      head_sha: run.head_sha,
      owner_id: ownerId,
      repository_id: repositoryId,
      workflow_path: run.path,
      workflow_ref: value.workflow_ref,
      ref: value.ref,
      outcome: "DENIED",
      fresh_runner: true,
      fresh_online_request: true,
      reached_google: true,
      rejection_category: "DISABLED_OR_INVALID_KEY",
      rejected_at: jobs[0].completed_at,
      log_sha256: createHash("sha256").update(log).digest("hex"),
    },
  };
}

export async function collectSuccessfulLegacyDeploy({
  owner,
  repository,
  runId,
  pullNumber,
  installationToken,
  fetchImpl = fetch,
}) {
  exact(owner, OWNER, "owner");
  exact(repository, REPOSITORY, "repository");
  exact(String(runId), NUMERIC, "run ID");
  if (!Number.isInteger(pullNumber) || pullNumber < 1) throw new Error("pull number is invalid");
  const token = requireGitHubInstallationToken(installationToken);
  const base = `https://api.github.com/repos/${owner}/${repository}`;
  const firstResponses = await Promise.all([
    fetchBaselineJson(`${base}/actions/runs/${runId}`, token, fetchImpl),
    fetchBaselineJson(`${base}/actions/runs/${runId}/jobs?per_page=100`, token, fetchImpl),
    fetchBaselineJson(`${base}/actions/runs/${runId}/approvals`, token, fetchImpl),
    fetchBaselineJson(`${base}/pulls/${pullNumber}`, token, fetchImpl),
    fetchBaselineJson(`${base}/pulls/${pullNumber}/reviews?per_page=100`, token, fetchImpl),
    fetchBaselineJson(`${base}/branches/main/protection`, token, fetchImpl),
  ]);
  const [run, jobsResponse, approvals, pull, reviews, protection] = firstResponses.map(({ value }) => value);
  const headSha = exact(run?.head_sha, SHA, "run head SHA");
  if (String(run?.id) !== String(runId) || run?.status !== "completed" || run?.conclusion !== "success"
      || run?.repository?.full_name !== `${owner}/${repository}` || run?.path !== BASELINE_WORKFLOW
      || run?.event !== "workflow_dispatch" || run?.head_branch !== "main"
      || !isRfc3339(run?.run_started_at) || !isRfc3339(run?.updated_at)
      || !timestampAtOrBefore(run.run_started_at, run.updated_at)) {
    throw new Error("legacy baseline run is not an authoritative completed protected-main dispatch");
  }
  const requiredChecks = protection?.required_status_checks?.checks;
  if (protection?.required_status_checks?.strict !== true || !Array.isArray(requiredChecks)
      || requiredChecks.length !== 1 || requiredChecks[0]?.context !== "test"
      || String(requiredChecks[0]?.app_id) !== "15368"
      || protection?.required_pull_request_reviews?.required_approving_review_count !== 1
      || protection?.required_pull_request_reviews?.dismiss_stale_reviews !== true
      || protection?.required_pull_request_reviews?.require_last_push_approval !== true
      || protection?.enforce_admins?.enabled !== true) {
    throw new Error("legacy baseline main branch protection is invalid");
  }
  const jobs = boundedGitHubPage(jobsResponse, "jobs").filter(({ name }) => name === "deploy");
  const job = jobs[0];
  const requiredSteps = [
    "Read the reviewed release marker",
    "Authenticate with the legacy key",
    "Deploy through the legacy key",
  ].map((name) => job?.steps?.findIndex((step) => step?.name === name));
  if (jobs.length !== 1 || job?.status !== "completed" || job?.conclusion !== "success"
      || !isGitHubHostedJob(job) || !isRfc3339(job?.started_at) || !isRfc3339(job?.completed_at)
      || !timestampAtOrBefore(run.run_started_at, job.started_at)
      || !timestampAtOrBefore(job.started_at, job.completed_at)
      || !timestampAtOrBefore(job.completed_at, run.updated_at)
      || requiredSteps.some((index) => index < 0)
      || !(requiredSteps[0] < requiredSteps[1] && requiredSteps[1] < requiredSteps[2])
      || requiredSteps.some((index) => job.steps[index].conclusion !== "success")) {
    throw new Error("legacy baseline job did not complete the reviewed legacy deployment");
  }
  const actorId = exact(String(run?.actor?.id), NUMERIC, "run actor ID");
  if (!Array.isArray(approvals) || approvals.length < 1 || approvals.length >= 100) {
    throw new Error("legacy baseline environment approvals are incomplete or unbounded");
  }
  const environmentApprovals = approvals.filter((approval) => approval?.state === "approved"
    && String(approval?.user?.id) !== actorId
    && approval?.environments?.some(({ name }) => name === "production"));
  if (environmentApprovals.length !== 1) throw new Error("legacy baseline independent production approval is missing or ambiguous");

  const pullHead = exact(pull?.head?.sha, SHA, "pull head SHA");
  const mergeSha = exact(pull?.merge_commit_sha, SHA, "pull merge SHA");
  if (pull?.number !== pullNumber || pull?.state !== "closed" || pull?.merged !== true
      || pull?.base?.ref !== "main" || pull?.base?.repo?.full_name !== `${owner}/${repository}`
      || !isRfc3339(pull?.merged_at) || !timestampBefore(pull.merged_at, run.run_started_at)) {
    throw new Error("legacy baseline workflow was not reviewed and merged before the run");
  }
  const authorId = exact(String(pull?.user?.id), NUMERIC, "pull author ID");
  if (!Array.isArray(reviews) || reviews.length < 1 || reviews.length >= 100) {
    throw new Error("legacy baseline pull reviews are incomplete or unbounded");
  }
  const pullApprovals = reviews.filter((review) => review?.state === "APPROVED"
    && review?.commit_id === pullHead && String(review?.user?.id) !== authorId
    && isRfc3339(review?.submitted_at) && timestampAtOrBefore(review.submitted_at, pull.merged_at));
  if (pullApprovals.length !== 1) throw new Error("legacy baseline workflow approval is missing or ambiguous");

  const contentResponses = await Promise.all([
    fetchBaselineJson(`${base}/contents/${BASELINE_WORKFLOW}?ref=${pullHead}`, token, fetchImpl),
    fetchBaselineJson(`${base}/contents/${BASELINE_WORKFLOW}?ref=${headSha}`, token, fetchImpl),
    fetchBaselineJson(`${base}/contents/demo/release.txt?ref=${headSha}`, token, fetchImpl),
  ]);
  const [reviewedContent, runContent, releaseContent] = contentResponses.map(({ value }) => value);
  const templateBytes = await readFile(BASELINE_TEMPLATE);
  const templateBlobSha = createHash("sha1")
    .update(Buffer.from(`blob ${templateBytes.length}\0`)).update(templateBytes).digest("hex");
  const template = githubWorkflowSnapshot({
    encoding: "base64",
    content: templateBytes.toString("base64"),
    sha: templateBlobSha,
  });
  const reviewed = githubWorkflowSnapshot(reviewedContent);
  const workflow = githubWorkflowSnapshot(runContent);
  if (reviewed.workflow_blob_sha !== template.workflow_blob_sha
      || reviewed.workflow_sha256 !== template.workflow_sha256
      || workflow.workflow_blob_sha !== template.workflow_blob_sha
      || workflow.workflow_sha256 !== template.workflow_sha256) {
    throw new Error("legacy baseline workflow bytes do not match the reviewed fixture");
  }
  const ownerId = exact(String(run?.repository?.owner?.id), NUMERIC, "repository owner ID");
  const repositoryId = exact(String(run?.repository?.id), NUMERIC, "repository ID");
  if (String(pull?.base?.repo?.owner?.id) !== ownerId || String(pull?.base?.repo?.id) !== repositoryId) {
    throw new Error("legacy baseline repository identity is invalid");
  }
  const observedTimes = [...firstResponses, ...contentResponses].map(({ observedAt: value }) => value);
  if (observedTimes.some((value) => !isRfc3339(value))) {
    throw new Error("legacy baseline observation time is invalid");
  }
  const observedAt = observedTimes.reduce((latest, value) => (
    timestampNanoseconds(value) > timestampNanoseconds(latest) ? value : latest
  ));
  if (!timestampAtOrBefore(run.updated_at, observedAt) || !timestampAtOrBefore(job.completed_at, observedAt)
      || !timestampAtOrBefore(pull.merged_at, observedAt)) {
    throw new Error("legacy baseline evidence occurrence is after collection");
  }
  const githubRun = {
    run_id: String(run.id),
    run_attempt: exact(String(run.run_attempt), NUMERIC, "run attempt"),
    head_sha: headSha,
    workflow_path: BASELINE_WORKFLOW,
    workflow_ref: `${owner}/${repository}/${BASELINE_WORKFLOW}@refs/heads/main`,
    workflow_blob_sha: workflow.workflow_blob_sha,
    workflow_sha256: workflow.workflow_sha256,
    owner_id: ownerId,
    repository_id: repositoryId,
    actor_id: actorId,
    event: "workflow_dispatch",
    ref: "refs/heads/main",
    environment: "production",
    conclusion: "success",
    runner_environment: "github-hosted",
    started_at: run.run_started_at,
    release_marker: githubReleaseMarker(releaseContent),
  };
  return {
    observedAt,
    workflowApproval: {
      number: pullNumber,
      head_sha: pullHead,
      merge_sha: mergeSha,
      workflow_path: BASELINE_WORKFLOW,
      workflow_blob_sha: reviewed.workflow_blob_sha,
      workflow_sha256: reviewed.workflow_sha256,
      owner_id: ownerId,
      repository_id: repositoryId,
      author_id: authorId,
      reviewer_id: exact(String(pullApprovals[0].user.id), NUMERIC, "reviewer ID"),
      review_commit_sha: pullApprovals[0].commit_id,
      reviewed_at: pullApprovals[0].submitted_at,
      merged_at: pull.merged_at,
      merged: true,
      reviewed: true,
    },
    githubRun,
    environmentReview: {
      run_id: githubRun.run_id,
      run_attempt: githubRun.run_attempt,
      head_sha: githubRun.head_sha,
      environment: "production",
      actor_id: actorId,
      reviewer_id: exact(String(environmentApprovals[0].user.id), NUMERIC, "environment reviewer ID"),
      state: "approved",
    },
  };
}
