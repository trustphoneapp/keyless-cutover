import { createHash } from "node:crypto";

import {
  downloadGitHubBytes,
  extractSingleJsonArtifact,
  fetchGitHubJson,
} from "./github-denial-evidence.mjs";
import { requireGitHubInstallationToken } from "./github-token.mjs";

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}$/;
const NUMERIC = /^\d+$/;
const KEY_ID = /^[a-f0-9]{40}$/;
const SHA = /^[a-f0-9]{40}$/;

function exact(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function provesGoogleKeyRejection(log) {
  const value = log.toString("utf8");
  return /(invalid_grant|Invalid JWT Signature|service account key .* disabled|key has been disabled)/i.test(value)
    && /(gcloud|oauth2|refreshing .* auth|google-github-actions\/auth)/i.test(value);
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
  const [run, jobsResponse, artifactsResponse] = await Promise.all([
    fetchGitHubJson(`${base}/actions/runs/${runId}`, token, fetchImpl),
    fetchGitHubJson(`${base}/actions/runs/${runId}/jobs?per_page=100`, token, fetchImpl),
    fetchGitHubJson(`${base}/actions/runs/${runId}/artifacts?per_page=100`, token, fetchImpl),
  ]);
  if (String(run?.id) !== String(runId) || run?.status !== "completed" || run?.conclusion !== "success"
      || run?.repository?.full_name !== `${owner}/${repository}` || String(run?.repository?.owner?.id) !== ownerId
      || String(run?.repository?.id) !== repositoryId || run?.path !== ".github/workflows/k0-legacy-auth-check.yml"
      || run?.event !== "workflow_dispatch" || run?.head_branch !== "main" || !exact(run?.head_sha, SHA, "head SHA")) {
    throw new Error("fresh legacy run does not match the scoped protected probe");
  }
  const jobs = jobsResponse?.jobs?.filter(({ name }) => name === "fresh-legacy-auth");
  if (!Array.isArray(jobs) || jobs.length !== 1 || jobs[0].status !== "completed" || jobs[0].conclusion !== "success"
      || jobs[0].steps?.find(({ name }) => name === "Require fresh legacy denial")?.conclusion !== "success") {
    throw new Error("fresh legacy denial assertion is missing or unsuccessful");
  }
  const artifacts = artifactsResponse?.artifacts?.filter((item) => item.name === "keyless-legacy-after-disable" && !item.expired);
  if (!Array.isArray(artifacts) || artifacts.length !== 1 || !Number.isInteger(artifacts[0].id)) {
    throw new Error("fresh legacy denial artifact is missing or ambiguous");
  }
  const [zip, log] = await Promise.all([
    downloadGitHubBytes(`${base}/actions/artifacts/${artifacts[0].id}/zip`, token, fetchImpl, 512_000),
    downloadGitHubBytes(`${base}/actions/jobs/${jobs[0].id}/logs`, token, fetchImpl, 1_000_000),
  ]);
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
      || !value.workflow_ref.includes("k0-legacy-auth-check.yml@refs/heads/main")) {
    throw new Error("fresh legacy denial artifact does not match the run and scoped key");
  }
  if (!provesGoogleKeyRejection(log)) throw new Error("fresh legacy log does not prove a Google key rejection");
  return {
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
    },
    googleAuthResult: {
      key_id: keyId,
      run_id: String(run.id),
      outcome: "DENIED",
      fresh_runner: true,
      fresh_online_request: true,
      log_sha256: createHash("sha256").update(log).digest("hex"),
    },
  };
}
