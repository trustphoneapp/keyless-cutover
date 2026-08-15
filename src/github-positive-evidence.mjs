import { createHash } from "node:crypto";

import { canonicalJson, decodeUtf8 } from "./evidence-artifact.mjs";
import {
  boundedGitHubPage,
  fetchGitHubJson,
  fetchGitHubJsonObserved,
  isGitHubHostedJob,
} from "./github-denial-evidence.mjs";
import { parseGitHubEvidenceCheckpointReceipt } from "./k0-evidence-normalizer.mjs";
import { verifyK0PreDisableArchive } from "./k0-predisable-archive.mjs";
import { githubReleaseMarker, githubWorkflowSnapshot } from "./github-workflow-snapshot.mjs";
import { requireGitHubReadToken } from "./github-token.mjs";
import { rejectDuplicateJsonKeys } from "./observation-time.mjs";
import { isRfc3339, timestampAtOrBefore, timestampBefore, timestampNanoseconds } from "./rfc3339.mjs";

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}$/;
const NUMERIC = /^\d+$/;
const SHA = /^[a-f0-9]{40}$/;
const WORKFLOW = /^\.github\/workflows\/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,62}\/)*[A-Za-z0-9][A-Za-z0-9._-]{0,62}\.ya?ml$/;
const CHECKPOINT_WORKFLOW = ".github/workflows/ci.yml";
const REQUIRED_CHECK = "test";
const REQUIRED_APP_ID = "15368";
const REQUIRED_APP_SLUG = "github-actions";
const MAX_CHECKPOINT_RESPONSE = 5 * 256 * 1024;
const MAX_ARCHIVE = 700 * 1024;
const CREDENTIAL = /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"private_key"\s*:|ya29\.[A-Za-z0-9._-]+|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|xapp-[0-9]+-[A-Za-z0-9-]{10,}|bearer\s+[A-Za-z0-9._~+/=-]{20,})/i;

function exact(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function exactEvidenceJsonPath(value, name) {
  const segments = typeof value === "string" ? value.split("/") : [];
  if (typeof value !== "string" || value.length > 256 || segments[0] !== "docs" || segments[1] !== "evidence"
      || segments.length < 3 || segments.some((segment) => !/^[A-Za-z0-9._-]+$/.test(segment)
        || segment === "." || segment === "..")
      || !/^[A-Za-z0-9._-]+\.json$/.test(segments.at(-1))) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function responseTime(value) {
  const milliseconds = typeof value === "string" ? Date.parse(value) : NaN;
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toUTCString() !== value) {
    throw new Error("GitHub response time is invalid");
  }
  return new Date(milliseconds).toISOString().replace(".000Z", "Z");
}

function captureCheckpointResponse(response) {
  try {
    if (!response || (typeof response !== "object" && typeof response !== "function")) {
      throw new Error("invalid response");
    }
    const status = response.status;
    const ok = response.ok;
    const headers = response.headers;
    const getHeader = headers?.get;
    if (typeof getHeader !== "function") throw new Error("invalid headers");
    const date = getHeader.call(headers, "date");
    const link = getHeader.call(headers, "link");
    const length = getHeader.call(headers, "content-length");
    if ((link !== null && typeof link !== "string")
        || (length !== null && typeof length !== "string")) throw new Error("invalid headers");
    const observedAt = responseTime(date);
    const body = response.body;
    const getReader = body?.getReader;
    const reader = typeof getReader === "function" ? getReader.call(body) : null;
    if (reader && typeof reader !== "object" && typeof reader !== "function") {
      throw new Error("invalid reader");
    }
    const read = reader?.read;
    const cancel = reader?.cancel;
    if (reader && (typeof read !== "function" || typeof cancel !== "function")) {
      throw new Error("invalid reader");
    }
    return { status, ok, link, length, observedAt, reader, read, cancel };
  } catch {
    throw new Error("GitHub API response primitives are invalid");
  }
}

async function cancelCheckpointReader(captured) {
  try {
    await captured?.cancel?.call(captured.reader);
  } catch {
    // The primary fixed error below must not disclose transport-controlled text.
  }
}

async function readCheckpointBody(captured) {
  const { length, reader, read } = captured;
  if (!reader || (length !== null && (length.length > 16 || !/^\d+$/.test(length)
      || Number(length) > MAX_CHECKPOINT_RESPONSE))) {
    await cancelCheckpointReader(captured);
    throw new Error("GitHub API response is too large or invalid");
  }
  const chunks = [];
  let total = 0;
  for (;;) {
    let done;
    let chunk;
    try {
      const part = await read.call(reader);
      if (!part || (typeof part !== "object" && typeof part !== "function")) {
        throw new Error("invalid body part");
      }
      done = part.done;
      const value = part.value;
      if (typeof done !== "boolean" || (done && value !== undefined)) {
        throw new Error("invalid body part");
      }
      if (!done) {
        if (!(value instanceof Uint8Array)) throw new Error("invalid body part");
        const byteLength = value.byteLength;
        if (!Number.isSafeInteger(byteLength) || byteLength < 0) throw new Error("invalid body part");
        chunk = Buffer.from(value);
        if (chunk.length !== byteLength) throw new Error("invalid body part");
      }
    } catch {
      await cancelCheckpointReader(captured);
      throw new Error("GitHub API response body is invalid");
    }
    if (done) break;
    total += chunk.length;
    if (total > MAX_CHECKPOINT_RESPONSE) {
      await cancelCheckpointReader(captured);
      throw new Error("GitHub API response is too large");
    }
    chunks.push(chunk);
  }
  if (length !== null && total !== Number(length)) {
    await cancelCheckpointReader(captured);
    throw new Error("GitHub API response length does not match Content-Length");
  }
  try {
    return Buffer.concat(chunks, total);
  } catch {
    throw new Error("GitHub API response body is invalid");
  }
}

async function fetchCheckpointJson(url, token, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(url, {
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${token}`,
        "x-github-api-version": "2022-11-28",
      },
      redirect: "error",
      signal: AbortSignal.timeout(8_000),
    });
  } catch {
    throw new Error("GitHub API transport failed");
  }
  const captured = captureCheckpointResponse(response);
  const { observedAt, status, ok, link } = captured;
  if (/rel="next"/.test(link ?? "")) {
    await cancelCheckpointReader(captured);
    throw new Error("GitHub API response is paginated");
  }
  if (ok !== true || status !== 200 || !captured.reader) {
    await cancelCheckpointReader(captured);
    throw new Error("GitHub API response is invalid");
  }
  const bytes = await readCheckpointBody(captured);
  let text;
  try {
    text = decodeUtf8(bytes);
    if (CREDENTIAL.test(text)) throw new Error("GitHub API response contains credential-shaped material");
    rejectDuplicateJsonKeys(text);
    return { value: JSON.parse(text), observedAt };
  } catch (error) {
    if (error?.message === "duplicate JSON key") {
      throw new Error("GitHub API response contains duplicate JSON keys");
    }
    if (/credential-shaped/.test(error?.message ?? "")) throw error;
    throw new Error("GitHub API response is not valid JSON");
  }
}

function boundedReviewPage(value) {
  if (!Array.isArray(value) || value.length >= 100) {
    throw new Error("GitHub review lookup is incomplete or unbounded");
  }
  return value;
}

function latestResponseTime(responses) {
  const times = responses.map(({ observedAt }) => observedAt);
  if (times.some((value) => !isRfc3339(value))) {
    throw new Error("GitHub observation time is invalid");
  }
  return times.reduce((latest, value) => (
    timestampNanoseconds(value) > timestampNanoseconds(latest) ? value : latest
  ));
}

function exactContentsBytes(value, path, name, maximum) {
  if (value?.encoding !== "base64" || value?.path !== path || typeof value.content !== "string"
      || !/^[A-Za-z0-9+/]+={0,2}$/.test(value.content) || !SHA.test(value.sha ?? "")) {
    throw new Error(`${name} content is invalid`);
  }
  const bytes = Buffer.from(value.content, "base64");
  const blobSha = createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
  if (!bytes.length || bytes.length > maximum || bytes.toString("base64") !== value.content
      || blobSha !== value.sha) {
    throw new Error(`${name} content is invalid`);
  }
  return { bytes, blobSha, encoded: value.content };
}

export async function collectGitHubWorkflowApproval({
  owner, repository, pullNumber, workflowPath, installationToken, fetchImpl = fetch,
}) {
  exact(owner, OWNER, "owner");
  exact(repository, REPOSITORY, "repository");
  if (!Number.isInteger(pullNumber) || pullNumber < 1) throw new Error("pull number is invalid");
  exact(workflowPath, WORKFLOW, "workflow path");
  const token = requireGitHubReadToken(installationToken);
  const base = `https://api.github.com/repos/${owner}/${repository}`;
  const [pull, reviews] = await Promise.all([
    fetchGitHubJson(`${base}/pulls/${pullNumber}`, token, fetchImpl),
    fetchGitHubJson(`${base}/pulls/${pullNumber}/reviews?per_page=100`, token, fetchImpl),
  ]);
  const headSha = exact(pull?.head?.sha, SHA, "pull head SHA");
  const mergeSha = exact(pull?.merge_commit_sha, SHA, "pull merge SHA");
  if (pull?.number !== pullNumber || pull?.state !== "closed" || pull?.merged !== true
      || pull?.base?.ref !== "main" || pull?.base?.repo?.full_name !== `${owner}/${repository}`
      || !isRfc3339(pull?.merged_at)) throw new Error("pull request is not an authoritative merged review");
  const authorId = exact(String(pull?.user?.id), NUMERIC, "pull author ID");
  const approvals = Array.isArray(reviews) ? reviews.filter((review) => review?.state === "APPROVED"
    && review?.commit_id === headSha && String(review?.user?.id) !== authorId
    && isRfc3339(review?.submitted_at) && timestampAtOrBefore(review.submitted_at, pull.merged_at)) : [];
  if (!approvals.length) throw new Error("independent commit-bound pull request approval is missing");
  approvals.sort((left, right) => left.submitted_at < right.submitted_at ? -1 : left.submitted_at > right.submitted_at ? 1 : 0);
  const snapshot = githubWorkflowSnapshot(await fetchGitHubJson(
    `${base}/contents/${workflowPath}?ref=${headSha}`,
    token,
    fetchImpl,
  ));
  return {
    number: pullNumber,
    head_sha: headSha,
    merge_sha: mergeSha,
    workflow_path: workflowPath,
    workflow_blob_sha: snapshot.workflow_blob_sha,
    workflow_sha256: snapshot.workflow_sha256,
    owner_id: exact(String(pull.base.repo.owner.id), NUMERIC, "repository owner ID"),
    repository_id: exact(String(pull.base.repo.id), NUMERIC, "repository ID"),
    author_id: authorId,
    reviewer_id: exact(String(approvals[0].user.id), NUMERIC, "reviewer ID"),
    review_commit_sha: approvals[0].commit_id,
    reviewed_at: approvals[0].submitted_at,
    merged_at: pull.merged_at,
    merged: true,
    reviewed: true,
  };
}

export async function collectGitHubSuccessfulDeploy({
  owner, repository, runId, workflowPath, environment, installationToken, fetchImpl = fetch,
}) {
  exact(owner, OWNER, "owner");
  exact(repository, REPOSITORY, "repository");
  exact(String(runId), NUMERIC, "run ID");
  exact(workflowPath, WORKFLOW, "workflow path");
  exact(environment, /^[A-Za-z0-9_-]{1,64}$/, "environment");
  const token = requireGitHubReadToken(installationToken);
  const base = `https://api.github.com/repos/${owner}/${repository}`;
  const firstResponses = await Promise.all([
    fetchGitHubJsonObserved(`${base}/actions/runs/${runId}`, token, fetchImpl),
    fetchGitHubJsonObserved(`${base}/actions/runs/${runId}/jobs?per_page=100`, token, fetchImpl),
    fetchGitHubJsonObserved(`${base}/actions/runs/${runId}/approvals`, token, fetchImpl),
  ]);
  const [run, jobsResponse, reviews] = firstResponses.map(({ value }) => value);
  const headSha = exact(run?.head_sha, SHA, "run head SHA");
  if (String(run?.id) !== String(runId) || run?.status !== "completed" || run?.conclusion !== "success"
      || run?.repository?.full_name !== `${owner}/${repository}` || run?.path !== workflowPath
      || run?.event !== "push" || run?.head_branch !== "main" || !isRfc3339(run?.run_started_at)) {
    throw new Error("GitHub deploy run is not an authoritative completed main push");
  }
  const allJobs = boundedGitHubPage(jobsResponse, "jobs");
  const jobs = allJobs.filter(({ name }) => name === "deploy");
  const job = jobs?.[0];
  const authSteps = job?.steps?.filter(({ name }) => name === "Authenticate through WIF") ?? [];
  const deploySteps = job?.steps?.filter(({ name }) => name === "Deploy through WIF") ?? [];
  if (jobs?.length !== 1 || job.status !== "completed" || job.conclusion !== "success"
      || !isGitHubHostedJob(job)
      || !isRfc3339(job.started_at) || !isRfc3339(job.completed_at)
      || !timestampAtOrBefore(run.run_started_at, job.started_at)
      || !timestampAtOrBefore(job.started_at, job.completed_at)
      || authSteps.length !== 1 || authSteps[0].conclusion !== "success"
      || deploySteps.length !== 1 || deploySteps[0].conclusion !== "success") {
    throw new Error("GitHub deploy job is not an authoritative hosted WIF deployment");
  }
  const actorId = exact(String(run?.actor?.id), NUMERIC, "run actor ID");
  const approval = Array.isArray(reviews) && reviews.find((review) => review?.state === "approved"
    && String(review?.user?.id) !== actorId && review.environments?.some(({ name }) => name === environment));
  if (!approval) throw new Error("independent deploy environment approval is missing");
  const contentResponses = await Promise.all([
    fetchGitHubJsonObserved(`${base}/contents/${workflowPath}?ref=${headSha}`, token, fetchImpl),
    fetchGitHubJsonObserved(`${base}/contents/demo/release.txt?ref=${headSha}`, token, fetchImpl),
  ]);
  const [workflowContent, releaseContent] = contentResponses.map(({ value }) => value);
  const observations = [...firstResponses, ...contentResponses].map(({ observedAt }) => observedAt);
  if (observations.some((value) => !timestampAtOrBefore(job.completed_at, value))) {
    throw new Error("GitHub deploy evidence occurrence is after collection");
  }
  const observedAt = observations.reduce((latest, value) => timestampAtOrBefore(latest, value) ? value : latest);
  const snapshot = githubWorkflowSnapshot(workflowContent);
  const githubRun = {
    run_id: String(run.id),
    run_attempt: exact(String(run.run_attempt), NUMERIC, "run attempt"),
    head_sha: headSha,
    workflow_path: workflowPath,
    workflow_ref: `${owner}/${repository}/${workflowPath}@refs/heads/main`,
    workflow_blob_sha: snapshot.workflow_blob_sha,
    workflow_sha256: snapshot.workflow_sha256,
    owner_id: exact(String(run.repository.owner.id), NUMERIC, "repository owner ID"),
    repository_id: exact(String(run.repository.id), NUMERIC, "repository ID"),
    actor_id: actorId,
    event: "push",
    ref: "refs/heads/main",
    environment,
    conclusion: "success",
    runner_environment: "github-hosted",
    started_at: run.run_started_at,
    release_marker: githubReleaseMarker(releaseContent),
  };
  return {
    observedAt,
    githubRun,
    environmentReview: {
      run_id: githubRun.run_id,
      run_attempt: githubRun.run_attempt,
      head_sha: githubRun.head_sha,
      environment,
      actor_id: actorId,
      reviewer_id: exact(String(approval.user.id), NUMERIC, "environment reviewer ID"),
      state: "approved",
    },
  };
}

export async function collectGitHubEvidenceCheckpoint({
  owner, repository, pullNumber, receiptPath, archivePath, installationToken, fetchImpl = fetch,
}) {
  exact(owner, OWNER, "owner");
  exact(repository, REPOSITORY, "repository");
  if (!Number.isInteger(pullNumber) || pullNumber < 1) throw new Error("pull number is invalid");
  exactEvidenceJsonPath(receiptPath, "receipt path");
  exactEvidenceJsonPath(archivePath, "archive path");
  if (archivePath === receiptPath) throw new Error("archive path must differ from receipt path");
  const token = requireGitHubReadToken(installationToken);
  const base = `https://api.github.com/repos/${owner}/${repository}`;
  const [protectionResponse, pullResponse, reviewsResponse] = await Promise.all([
    fetchCheckpointJson(`${base}/branches/main/protection`, token, fetchImpl),
    fetchCheckpointJson(`${base}/pulls/${pullNumber}`, token, fetchImpl),
    fetchCheckpointJson(`${base}/pulls/${pullNumber}/reviews?per_page=100`, token, fetchImpl),
  ]);
  const pull = pullResponse.value;
  const protection = protectionResponse.value;
  const requiredChecks = protection?.required_status_checks?.checks;
  if (protection?.required_status_checks?.strict !== true || !Array.isArray(requiredChecks)
      || requiredChecks.length !== 1 || requiredChecks[0]?.context !== REQUIRED_CHECK
      || String(requiredChecks[0]?.app_id) !== REQUIRED_APP_ID
      || protection?.required_pull_request_reviews?.required_approving_review_count !== 1
      || protection?.required_pull_request_reviews?.dismiss_stale_reviews !== true
      || protection?.required_pull_request_reviews?.require_last_push_approval !== true
      || protection?.enforce_admins?.enabled !== true
      || protection?.required_linear_history?.enabled !== true) {
    throw new Error("main branch protection does not match the checkpoint policy");
  }
  const headSha = exact(pull?.head?.sha, SHA, "pull head SHA");
  const mergeSha = exact(pull?.merge_commit_sha, SHA, "pull merge SHA");
  if (pull?.number !== pullNumber || pull?.state !== "closed" || pull?.merged !== true
      || pull?.base?.ref !== "main" || pull?.base?.repo?.full_name !== `${owner}/${repository}`
      || !isRfc3339(pull?.merged_at)) throw new Error("checkpoint pull request is not authoritatively merged");
  const authorId = exact(String(pull?.user?.id), NUMERIC, "pull author ID");
  const approvals = boundedReviewPage(reviewsResponse.value).filter((review) => review?.state === "APPROVED"
    && review?.commit_id === headSha && String(review?.user?.id) !== authorId
    && isRfc3339(review?.submitted_at) && timestampAtOrBefore(review.submitted_at, pull.merged_at));
  if (approvals.length !== 1) throw new Error("checkpoint pull request approval is missing or ambiguous");

  const encodedReceiptPath = receiptPath.split("/").map(encodeURIComponent).join("/");
  const encodedArchivePath = archivePath.split("/").map(encodeURIComponent).join("/");
  const [reviewedReceiptResponse, receiptResponse, reviewedArchiveResponse, archiveResponse, runsResponse, checksResponse] = await Promise.all([
    fetchCheckpointJson(`${base}/contents/${encodedReceiptPath}?ref=${headSha}`, token, fetchImpl),
    fetchCheckpointJson(`${base}/contents/${encodedReceiptPath}?ref=${mergeSha}`, token, fetchImpl),
    fetchCheckpointJson(`${base}/contents/${encodedArchivePath}?ref=${headSha}`, token, fetchImpl),
    fetchCheckpointJson(`${base}/contents/${encodedArchivePath}?ref=${mergeSha}`, token, fetchImpl),
    fetchCheckpointJson(`${base}/actions/runs?branch=main&event=push&head_sha=${mergeSha}&per_page=100&status=completed`, token, fetchImpl),
    fetchCheckpointJson(`${base}/commits/${mergeSha}/check-runs?per_page=100`, token, fetchImpl),
  ]);
  const content = receiptResponse.value;
  const receiptContent = exactContentsBytes(content, receiptPath, "checkpoint receipt", 64 * 1024);
  const reviewedContent = reviewedReceiptResponse.value;
  const reviewedReceipt = exactContentsBytes(reviewedContent, receiptPath, "reviewed checkpoint receipt", 64 * 1024);
  if (reviewedReceipt.blobSha !== receiptContent.blobSha || reviewedReceipt.encoded !== receiptContent.encoded) {
    throw new Error("checkpoint receipt differs from its reviewed head");
  }
  const receipt = parseGitHubEvidenceCheckpointReceipt(receiptContent.bytes);
  if (receipt.receipt_blob_sha !== receiptContent.blobSha || receipt.receipt_bytes_base64 !== receiptContent.encoded) {
    throw new Error("checkpoint receipt blob does not match its bytes");
  }

  const archiveContent = exactContentsBytes(archiveResponse.value, archivePath, "pre-disable archive", MAX_ARCHIVE);
  const reviewedArchive = exactContentsBytes(
    reviewedArchiveResponse.value, archivePath, "reviewed pre-disable archive", MAX_ARCHIVE,
  );
  if (reviewedArchive.blobSha !== archiveContent.blobSha || reviewedArchive.encoded !== archiveContent.encoded) {
    throw new Error("pre-disable archive differs from its reviewed head");
  }
  const archiveBytes = Buffer.from(archiveContent.bytes);
  await verifyK0PreDisableArchive(archiveBytes);
  const archive = JSON.parse(decodeUtf8(archiveBytes));
  const scanIds = archive.evidence.filter(({ kind }) => kind === "LEAK_SCAN").map(({ id }) => id);
  const preEvidence = archive.evidence.filter(({ id }) => id !== scanIds[0]);
  const records = new Map(receipt.receipt.evidence.map((record) => [record.id, record]));
  const archivedArtifacts = new Map(archive.artifacts.map(({ id, bytes_base64: bytesBase64 }) => [
    id, JSON.parse(decodeUtf8(Buffer.from(bytesBase64, "base64"))),
  ]));
  if (scanIds.length !== 1 || records.size !== preEvidence.length
      || [...records.keys()].some((id) => !preEvidence.some((entry) => entry.id === id))) {
    throw new Error("checkpoint receipt does not exactly cover the pre-disable archive");
  }
  for (const entry of preEvidence) {
    const record = records.get(entry.id);
    const artifact = archivedArtifacts.get(entry.id);
    const dataSha256 = artifact?.data === undefined ? null
      : createHash("sha256").update(canonicalJson(artifact.data)).digest("hex");
    if (record?.kind !== entry.kind || record?.locator !== entry.locator || record?.data_sha256 !== dataSha256
        || !timestampAtOrBefore(record?.recorded_at, artifact?.observed_at)
        || !timestampAtOrBefore(record?.recorded_at, archive.sealed_at)
        || !timestampAtOrBefore(record?.recorded_at, approvals[0].submitted_at)) {
      throw new Error("checkpoint receipt does not match the pre-disable archive evidence");
    }
  }
  if (!timestampAtOrBefore(archive.sealed_at, approvals[0].submitted_at)) {
    throw new Error("pre-disable archive was sealed after checkpoint review");
  }

  const runs = boundedGitHubPage(runsResponse.value, "workflow_runs").filter((candidate) =>
    candidate?.path === CHECKPOINT_WORKFLOW && candidate?.head_sha === mergeSha);
  if (runs.length !== 1) throw new Error("checkpoint main push run is missing or ambiguous");
  const run = runs[0];
  if (run?.repository?.full_name !== `${owner}/${repository}` || run?.event !== "push"
      || run?.head_branch !== "main" || run?.status !== "completed" || run?.conclusion !== "success"
      || !isRfc3339(run?.run_started_at) || !isRfc3339(run?.updated_at)
      || !timestampAtOrBefore(pull.merged_at, run.run_started_at)
      || !timestampAtOrBefore(run.run_started_at, run.updated_at)) {
    throw new Error("checkpoint main push run is invalid");
  }
  const runId = exact(String(run?.id), NUMERIC, "checkpoint run ID");
  const runAttempt = exact(String(run?.run_attempt), NUMERIC, "checkpoint run attempt");

  const checks = boundedGitHubPage(checksResponse.value, "check_runs")
    .filter((candidate) => candidate?.name === REQUIRED_CHECK && candidate?.head_sha === mergeSha);
  if (checks.length !== 1) throw new Error("checkpoint required check is missing or ambiguous");
  const check = checks[0];
  const detailsPrefix = `https://github.com/${owner}/${repository}/actions/runs/${runId}/job/`;
  if (String(check?.app?.id) !== REQUIRED_APP_ID || check?.app?.slug !== REQUIRED_APP_SLUG
      || check?.status !== "completed" || check?.conclusion !== "success"
      || typeof check?.details_url !== "string" || !check.details_url.startsWith(detailsPrefix)
      || !/^\d+$/.test(check.details_url.slice(detailsPrefix.length))
      || !isRfc3339(check?.started_at) || !isRfc3339(check?.completed_at)
      || !timestampAtOrBefore(run.run_started_at, check.started_at)
      || !timestampAtOrBefore(check.started_at, check.completed_at)
      || !timestampAtOrBefore(check.completed_at, run.updated_at)) {
    throw new Error("checkpoint required check is invalid");
  }
  const repositoryId = exact(String(pull?.base?.repo?.id), NUMERIC, "repository ID");
  const ownerId = exact(String(pull?.base?.repo?.owner?.id), NUMERIC, "repository owner ID");
  if (String(run?.repository?.id) !== repositoryId || String(run?.repository?.owner?.id) !== ownerId) {
    throw new Error("checkpoint run repository identity is invalid");
  }
  const collectedAt = latestResponseTime([
    protectionResponse, pullResponse, reviewsResponse, reviewedReceiptResponse, receiptResponse,
    reviewedArchiveResponse, archiveResponse, runsResponse, checksResponse,
  ]);
  if (!timestampBefore(approvals[0].submitted_at, pull.merged_at)
      || !timestampBefore(approvals[0].submitted_at, run.run_started_at)
      || !timestampBefore(approvals[0].submitted_at, check.started_at)
      || !timestampBefore(approvals[0].submitted_at, collectedAt)) {
    throw new Error("checkpoint archive review timeline is invalid");
  }
  return {
    observedAt: collectedAt,
    archiveBytes: Buffer.from(archiveBytes),
    checkpoint: {
      owner_id: ownerId,
      repository_id: repositoryId,
      collected_at: collectedAt,
      protection: {
        branch: "main",
        required_status_checks_strict: true,
        required_check_name: REQUIRED_CHECK,
        required_check_app_id: REQUIRED_APP_ID,
        required_approving_review_count: 1,
        dismiss_stale_reviews: true,
        require_last_push_approval: true,
        enforce_admins: true,
        required_linear_history: true,
      },
      pull: {
        number: pullNumber,
        head_sha: headSha,
        merge_sha: mergeSha,
        author_id: authorId,
        reviewer_id: exact(String(approvals[0].user.id), NUMERIC, "reviewer ID"),
        review_commit_sha: approvals[0].commit_id,
        reviewed_at: approvals[0].submitted_at,
        merged_at: pull.merged_at,
      },
      receipt: {
        path: receiptPath,
        blob_sha: receipt.receipt_blob_sha,
        sha256: receipt.receipt_sha256,
        bytes_base64: receipt.receipt_bytes_base64,
      },
      archive: {
        path: archivePath,
        blob_sha: archiveContent.blobSha,
        sha256: createHash("sha256").update(archiveBytes).digest("hex"),
        ledger_sha256: archive.ledger_sha256,
        artifact_bytes_sha256: archive.artifact_bytes_sha256,
        sealed_at: archive.sealed_at,
        transaction_id: archive.transaction_id,
        nonce: archive.nonce,
      },
      run: {
        run_id: runId,
        run_attempt: runAttempt,
        head_sha: mergeSha,
        workflow_path: CHECKPOINT_WORKFLOW,
        event: "push",
        ref: "refs/heads/main",
        status: "completed",
        conclusion: "success",
        started_at: run.run_started_at,
        completed_at: run.updated_at,
      },
      check: {
        name: REQUIRED_CHECK,
        app_id: REQUIRED_APP_ID,
        app_slug: REQUIRED_APP_SLUG,
        head_sha: mergeSha,
        status: "completed",
        conclusion: "success",
        started_at: check.started_at,
        completed_at: check.completed_at,
        details_url: check.details_url,
      },
    },
  };
}
