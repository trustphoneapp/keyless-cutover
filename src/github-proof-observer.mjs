import { requireGitHubInstallationToken } from "./github-token.mjs";

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}$/;
const RUN_ID = /^\d+$/;
const WORKFLOW_PATH = /^\.github\/workflows\/[A-Za-z0-9._/-]+\.ya?ml$/;
const MAX_RESPONSE_BYTES = 512_000;

function exact(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

async function json(url, token, fetchImpl) {
  const response = await fetchImpl(url, {
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${token}`,
      "x-github-api-version": "2022-11-28",
    },
    redirect: "error",
    signal: AbortSignal.timeout(5_000),
  });
  if (!response.ok) throw new Error(`GitHub evidence lookup failed with HTTP ${response.status}`);
  const body = await response.text();
  if (body.length > MAX_RESPONSE_BYTES) throw new Error("GitHub evidence response is too large");
  return JSON.parse(body);
}

function workflowSource(content) {
  if (content?.encoding !== "base64" || typeof content.content !== "string") {
    throw new Error("GitHub workflow content is invalid");
  }
  const source = Buffer.from(content.content.replace(/\s/g, ""), "base64").toString("utf8");
  if (Buffer.byteLength(source) > 64 * 1024) throw new Error("GitHub workflow is too large");
  return source;
}

function approvedEnvironment(reviews, environment, actorId) {
  if (!Array.isArray(reviews)) throw new Error("GitHub review history is invalid");
  return reviews.some((review) => review?.state === "approved"
    && String(review?.user?.id) !== actorId
    && review.environments?.some(({ name }) => name === environment));
}

export async function fetchGitHubProofObservation({
  owner,
  repository,
  runId,
  workflowPath,
  environment,
  token,
  fetchImpl = fetch,
}) {
  exact(owner, OWNER, "owner");
  exact(repository, REPOSITORY, "repository");
  exact(String(runId), RUN_ID, "run_id");
  exact(workflowPath, WORKFLOW_PATH, "workflow_path");
  exact(environment, /^[A-Za-z0-9_-]{1,64}$/, "environment");
  requireGitHubInstallationToken(token);
  const base = `https://api.github.com/repos/${owner}/${repository}`;
  const run = await json(`${base}/actions/runs/${runId}`, token, fetchImpl);
  if (String(run?.id) !== String(runId) || run?.status !== "completed" || run?.conclusion !== "success") {
    throw new Error("GitHub run is not a completed success");
  }
  if (run?.path !== workflowPath || run?.repository?.full_name !== `${owner}/${repository}`) {
    throw new Error("GitHub run repository or workflow path does not match");
  }
  const headSha = exact(run.head_sha, /^[a-f0-9]{40}$/, "head_sha");
  const [content, reviews] = await Promise.all([
    json(`${base}/contents/${workflowPath}?ref=${headSha}`, token, fetchImpl),
    json(`${base}/actions/runs/${runId}/approvals`, token, fetchImpl),
  ]);
  const source = workflowSource(content);
  if (!/^\s*runs-on:\s*ubuntu-latest\s*$/m.test(source) || source.includes("self-hosted")) {
    throw new Error("proof workflow is not fixed to a GitHub-hosted runner");
  }
  if (!new RegExp(`^\\s*environment:\\s*${environment}\\s*$`, "m").test(source)) {
    throw new Error("proof workflow does not use the expected environment");
  }
  const actorId = exact(String(run?.actor?.id), RUN_ID, "actor_id");
  if (!approvedEnvironment(reviews, environment, actorId)) {
    throw new Error("independent environment approval is missing");
  }
  const ref = `refs/heads/${exact(run.head_branch, /^[A-Za-z0-9._/-]+$/, "head_branch")}`;
  return {
    owner_id: exact(String(run?.repository?.owner?.id), RUN_ID, "owner_id"),
    repository_id: exact(String(run?.repository?.id), RUN_ID, "repository_id"),
    workflow_path: workflowPath,
    workflow_ref: `${owner}/${repository}/${workflowPath}@${ref}`,
    workflow_blob_sha: exact(content.sha, /^[a-f0-9]{40}$/, "workflow_blob_sha"),
    head_sha: headSha,
    run_id: String(run.id),
    run_attempt: exact(String(run.run_attempt), RUN_ID, "run_attempt"),
    actor_id: actorId,
    triggering_actor: exact(run?.triggering_actor?.login, /^[A-Za-z0-9-]{1,39}$/, "triggering_actor"),
    event_name: exact(run.event, /^[a-z_]+$/, "event_name"),
    ref,
    environment,
    runner_environment: "github-hosted",
  };
}
