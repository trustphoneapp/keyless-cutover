import { requireGitHubReadToken } from "./github-token.mjs";
import { boundedGitHubPage, isGitHubHostedJob } from "./github-denial-evidence.mjs";
import { githubWorkflowSnapshot } from "./github-workflow-snapshot.mjs";
import { rejectDuplicateJsonKeys } from "./observation-time.mjs";
import { isRfc3339, timestampAtOrBefore } from "./rfc3339.mjs";
import { CREDENTIAL_SHAPED as CREDENTIAL } from "./credential-shaped.mjs";
import { decodeUtf8 } from "./evidence-artifact.mjs";

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}$/;
const RUN_ID = /^\d+$/;
const WORKFLOW_PATH = /^\.github\/workflows\/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,62}\/)*[A-Za-z0-9][A-Za-z0-9._-]{0,62}\.ya?ml$/;
const MAX_RESPONSE_BYTES = 512_000;

function exact(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

async function json(url, token, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(url, {
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${token}`,
        "x-github-api-version": "2022-11-28",
      },
      redirect: "error",
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    throw new Error("GitHub evidence transport failed");
  }
  let ok;
  let status;
  let declared;
  let reader;
  try {
    ok = response?.ok;
    status = response?.status;
    declared = response?.headers?.get?.("content-length") ?? null;
    reader = response?.body?.getReader?.();
  } catch {
    throw new Error("GitHub evidence response primitives are invalid");
  }
  if (!ok) throw new Error(`GitHub evidence lookup failed with HTTP ${status}`);
  if (declared !== null && (typeof declared !== "string" || declared.length > 16
      || !/^\d+$/.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)) {
    throw new Error("GitHub evidence response is too large");
  }
  let bytes;
  if (reader) {
    const chunks = [];
    let total = 0;
    try {
      for (;;) {
        const part = await reader.read();
        if (!part || typeof part !== "object" || typeof part.done !== "boolean") throw new Error("invalid body");
        if (part.done) break;
        if (!(part.value instanceof Uint8Array)) throw new Error("invalid body");
        const chunk = Buffer.from(part.value);
        total += chunk.length;
        if (total > MAX_RESPONSE_BYTES) throw new Error("too large");
        chunks.push(chunk);
      }
    } catch {
      try { await reader.cancel(); } catch { /* static failure below */ }
      throw new Error("GitHub evidence response body is invalid or too large");
    }
    if (declared !== null && total !== Number(declared)) {
      throw new Error("GitHub evidence response length does not match Content-Length");
    }
    bytes = Buffer.concat(chunks, total);
  } else {
    if (declared === null) throw new Error("GitHub evidence response body is unavailable");
    let body;
    try {
      body = await response.text();
      if (typeof body !== "string") throw new Error("invalid body");
    } catch { throw new Error("GitHub evidence response body is invalid"); }
    bytes = Buffer.from(body);
    if (bytes.length > MAX_RESPONSE_BYTES || bytes.length !== Number(declared)) {
      throw new Error(bytes.length > MAX_RESPONSE_BYTES
        ? "GitHub evidence response is too large"
        : "GitHub evidence response length does not match Content-Length");
    }
  }
  let body;
  try { body = decodeUtf8(bytes); } catch { throw new Error("GitHub evidence response is not valid UTF-8"); }
  if (CREDENTIAL.test(body)) throw new Error("GitHub evidence response contains credential-shaped material");
  try {
    rejectDuplicateJsonKeys(body);
    return JSON.parse(body);
  } catch (error) {
    if (error?.message === "duplicate JSON key") throw new Error("GitHub evidence response contains duplicate JSON keys");
    throw new Error("GitHub evidence response is not valid JSON");
  }
}

function workflowSource(content) {
  return githubWorkflowSnapshot(content);
}

function approvedEnvironment(reviews, environment, actorId) {
  if (!Array.isArray(reviews)) throw new Error("GitHub review history is invalid");
  return reviews.find((review) => review?.state === "approved"
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
  requireGitHubReadToken(token);
  const base = `https://api.github.com/repos/${owner}/${repository}`;
  const run = await json(`${base}/actions/runs/${runId}`, token, fetchImpl);
  if (String(run?.id) !== String(runId) || run?.status !== "completed" || run?.conclusion !== "success") {
    throw new Error("GitHub run is not a completed success");
  }
  if (run?.path !== workflowPath || run?.repository?.full_name !== `${owner}/${repository}`) {
    throw new Error("GitHub run repository or workflow path does not match");
  }
  const headSha = exact(run.head_sha, /^[a-f0-9]{40}$/, "head_sha");
  const [content, reviews, jobsResponse] = await Promise.all([
    json(`${base}/contents/${workflowPath}?ref=${headSha}`, token, fetchImpl),
    json(`${base}/actions/runs/${runId}/approvals`, token, fetchImpl),
    json(`${base}/actions/runs/${runId}/jobs?per_page=100`, token, fetchImpl),
  ]);
  const snapshot = workflowSource(content);
  const source = snapshot.bytes.toString("utf8");
  if (!/^\s*runs-on:\s*ubuntu-latest\s*$/m.test(source) || source.includes("self-hosted")) {
    throw new Error("proof workflow is not fixed to a GitHub-hosted runner");
  }
  if (!new RegExp(`^\\s*environment:\\s*${environment}\\s*$`, "m").test(source)) {
    throw new Error("proof workflow does not use the expected environment");
  }
  const jobs = boundedGitHubPage(jobsResponse, "jobs").filter(({ name }) => name === "proof");
  if (jobs.length !== 1 || jobs[0].status !== "completed" || jobs[0].conclusion !== "success"
      || !isGitHubHostedJob(jobs[0])) {
    throw new Error("ProofV2 job is not an authoritative hosted success");
  }
  if (!isRfc3339(run.run_started_at) || !isRfc3339(jobs[0].started_at) || !isRfc3339(jobs[0].completed_at)
      || !timestampAtOrBefore(run.run_started_at, jobs[0].started_at)
      || !timestampAtOrBefore(jobs[0].started_at, jobs[0].completed_at)) {
    throw new Error("ProofV2 job timeline is invalid");
  }
  const actorId = exact(String(run?.actor?.id), RUN_ID, "actor_id");
  const approval = approvedEnvironment(reviews, environment, actorId);
  if (!approval) {
    throw new Error("independent environment approval is missing");
  }
  const ref = `refs/heads/${exact(run.head_branch, /^[A-Za-z0-9._/-]+$/, "head_branch")}`;
  return {
    owner_id: exact(String(run?.repository?.owner?.id), RUN_ID, "owner_id"),
    repository_id: exact(String(run?.repository?.id), RUN_ID, "repository_id"),
    workflow_path: workflowPath,
    workflow_ref: `${owner}/${repository}/${workflowPath}@${ref}`,
    workflow_blob_sha: snapshot.workflow_blob_sha,
    workflow_sha256: snapshot.workflow_sha256,
    head_sha: headSha,
    run_id: String(run.id),
    run_attempt: exact(String(run.run_attempt), RUN_ID, "run_attempt"),
    actor_id: actorId,
    triggering_actor: exact(run?.triggering_actor?.login, /^[A-Za-z0-9-]{1,39}$/, "triggering_actor"),
    event_name: exact(run.event, /^workflow_dispatch$/, "event_name"),
    ref,
    environment,
    runner_environment: "github-hosted",
    started_at: run.run_started_at,
    release_marker: null,
    environment_review: {
      state: "approved",
      environment,
      reviewer_id: exact(String(approval.user.id), RUN_ID, "reviewer_id"),
      reviewer_login: exact(approval.user.login, /^[A-Za-z0-9-]{1,39}$/, "reviewer_login"),
    },
  };
}
