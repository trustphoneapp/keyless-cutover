import { createHash } from "node:crypto";
import AdmZip from "adm-zip";
import { decodeUtf8 } from "./evidence-artifact.mjs";
import { requireGitHubReadToken } from "./github-token.mjs";
import { githubReleaseMarker, githubWorkflowSnapshot } from "./github-workflow-snapshot.mjs";
import { isRfc3339, timestampAtOrBefore, timestampNanoseconds } from "./rfc3339.mjs";

// The redirected download response and the initial redirect response come from independent
// services (github.com and the CDN backing the redirect target, e.g. blob.core.windows.net),
// whose clocks are not sub-second synchronized. Confirmed live: a job-logs download observed
// one second before its own redirect, on an otherwise valid, immediately-fetched response.
// This bounds ordinary cross-service clock skew without weakening the freshness check itself:
// the download must still land within a few seconds of the redirect that produced it.
const REDIRECT_CLOCK_SKEW_TOLERANCE_NS = 5n * 1_000_000_000n;
const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}$/;
const NUMERIC = /^\d+$/;
const SHA = /^[a-f0-9]{40}$/;
const SERVICE = /^[a-z][a-z0-9-]{0,62}$/;
const PROVIDER = /^projects\/\d+\/locations\/global\/workloadIdentityPools\/[a-z0-9-]+\/providers\/[a-z0-9-]+$/;
const CREDENTIAL = /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"private_key"\s*:|ya29\.[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35})/;
const MAX_JSON_RESPONSE = 1_000_000;
const JOBS = {
  H1: "external-identity",
  H2: "external-identity",
  H3: "h3-wrong-ref",
  H4: "hostile",
  H5: "h5-wrong-event",
  H6: "h6-wrong-environment",
  H7: "h7-wrong-audience",
  H8: "h8-forbidden-resource",
};

function exact(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function headers(token) {
  return {
    accept: "application/vnd.github+json",
    authorization: `Bearer ${token}`,
    "x-github-api-version": "2022-11-28",
  };
}

function responseTime(value) {
  const milliseconds = typeof value === "string" ? Date.parse(value) : NaN;
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toUTCString() !== value) {
    throw new Error("GitHub response time is invalid");
  }
  return new Date(milliseconds).toISOString().replace(".000Z", "Z");
}

function captureBodyResponse(response, name) {
  try {
    const responseHeaders = response?.headers;
    const observedAt = responseTime(responseHeaders?.get?.("date"));
    const status = response?.status;
    const ok = response?.ok;
    const length = responseHeaders?.get?.("content-length");
    const body = response?.body;
    const reader = body && typeof body.getReader === "function" ? body.getReader() : null;
    return { observedAt, status, ok, length, reader };
  } catch {
    throw new Error(`${name} primitives are invalid`);
  }
}

function rejectDuplicateJsonKeys(text) {
  let index = 0;
  const whitespace = () => { while (/[\t\n\r ]/.test(text[index] ?? "")) index += 1; };
  const string = () => {
    const start = index;
    if (text[index] !== '"') throw new Error("invalid JSON");
    index += 1;
    for (;;) {
      const character = text[index];
      if (character === undefined || /[\u0000-\u001f]/u.test(character)) throw new Error("invalid JSON");
      if (character === '"') {
        index += 1;
        return JSON.parse(text.slice(start, index));
      }
      if (character === "\\") {
        index += 1;
        if (!/["\\/bfnrtu]/.test(text[index] ?? "")) throw new Error("invalid JSON");
        if (text[index] === "u") {
          if (!/^[a-f0-9]{4}$/i.test(text.slice(index + 1, index + 5))) throw new Error("invalid JSON");
          index += 4;
        }
      }
      index += 1;
    }
  };
  const value = (depth) => {
    if (depth > 64) throw new Error("invalid JSON");
    whitespace();
    if (text[index] === "{") {
      index += 1;
      whitespace();
      const keys = new Set();
      if (text[index] === "}") { index += 1; return; }
      for (;;) {
        whitespace();
        const key = string();
        if (keys.has(key)) throw new Error("duplicate JSON key");
        keys.add(key);
        whitespace();
        if (text[index] !== ":") throw new Error("invalid JSON");
        index += 1;
        value(depth + 1);
        whitespace();
        if (text[index] === "}") { index += 1; return; }
        if (text[index] !== ",") throw new Error("invalid JSON");
        index += 1;
      }
    }
    if (text[index] === "[") {
      index += 1;
      whitespace();
      if (text[index] === "]") { index += 1; return; }
      for (;;) {
        value(depth + 1);
        whitespace();
        if (text[index] === "]") { index += 1; return; }
        if (text[index] !== ",") throw new Error("invalid JSON");
        index += 1;
      }
    }
    if (text[index] === '"') { string(); return; }
    for (const literal of ["true", "false", "null"]) {
      if (text.startsWith(literal, index)) { index += literal.length; return; }
    }
    const number = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(index));
    if (!number) throw new Error("invalid JSON");
    index += number[0].length;
  };
  value(0);
  whitespace();
  if (index !== text.length) throw new Error("invalid JSON");
}

async function readBoundedBody({ reader, length }, limit, name) {
  const invalidLength = length !== null && (typeof length !== "string" || length.length > 16
    || !/^\d+$/.test(length) || Number(length) > limit);
  if (!reader || invalidLength) {
    try { await reader?.cancel(); } catch { /* static failure below */ }
    throw new Error(`${name} is invalid or too large`);
  }
  const chunks = [];
  let total = 0;
  for (;;) {
    let done;
    let chunk;
    try {
      const part = await reader.read();
      if (!part || (typeof part !== "object" && typeof part !== "function")) throw new Error("invalid body part");
      done = part.done;
      const value = part.value;
      if (typeof done !== "boolean" || (done && value !== undefined)) throw new Error("invalid body part");
      if (!done) {
        if (!(value instanceof Uint8Array)) throw new Error("invalid body part");
        const byteLength = value.byteLength;
        if (!Number.isSafeInteger(byteLength) || byteLength < 0) throw new Error("invalid body part");
        chunk = Buffer.from(value);
        if (chunk.length !== byteLength) throw new Error("invalid body part");
      }
    } catch {
      try { await reader.cancel(); } catch { /* static failure below */ }
      throw new Error(`${name} body is invalid`);
    }
    if (done) break;
    total += chunk.length;
    if (total > limit) {
      try { await reader.cancel(); } catch { /* static failure below */ }
      throw new Error(`${name} is too large`);
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, total);
}

export async function fetchGitHubJsonObserved(url, token, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(url, {
      headers: headers(token), redirect: "error", signal: AbortSignal.timeout(8_000),
    });
  } catch {
    throw new Error("GitHub API transport failed");
  }
  const captured = captureBodyResponse(response, "GitHub API response");
  const { observedAt, status, ok } = captured;
  if (status !== 200 || ok !== true) {
    try { await captured.reader?.cancel(); } catch { /* static failure below */ }
    throw new Error("GitHub API response is invalid");
  }
  const bytes = await readBoundedBody(captured, MAX_JSON_RESPONSE, "GitHub API response");
  let text;
  try {
    text = decodeUtf8(bytes);
  } catch {
    throw new Error("GitHub API response is not valid UTF-8");
  }
  if (CREDENTIAL.test(text)) throw new Error("GitHub API response contains credential-shaped material");
  try {
    rejectDuplicateJsonKeys(text);
    return { value: JSON.parse(text), observedAt };
  } catch {
    throw new Error("GitHub API response is not valid JSON");
  }
}

export async function fetchGitHubJson(url, token, fetchImpl) {
  const response = await fetchImpl(url, { headers: headers(token), redirect: "error", signal: AbortSignal.timeout(8_000) });
  const text = await response.text();
  if (text.length > MAX_JSON_RESPONSE) throw new Error("GitHub API response is too large");
  if (!response.ok) throw new Error(`GitHub API failed with HTTP ${response.status}`);
  return JSON.parse(text);
}

export function boundedGitHubPage(response, field) {
  const items = response?.[field];
  if (!Array.isArray(items) || !Number.isInteger(response?.total_count)
      || response.total_count < 0 || response.total_count > 100 || response.total_count !== items.length) {
    throw new Error("GitHub list lookup is incomplete or unbounded");
  }
  return items;
}

export function isGitHubHostedJob(job) {
  return job?.runner_group_name === "GitHub Actions"
    && Array.isArray(job.labels) && job.labels.includes("ubuntu-latest");
}

function trustedDownloadUrl(location) {
  if (typeof location !== "string" || location.length > 8_192 || !location.startsWith("https://")
      || /[\u0000-\u001f\u007f\\#]/u.test(location)) {
    throw new Error("GitHub download redirect is not trusted");
  }
  const authorityEnd = [location.indexOf("/", 8), location.indexOf("?", 8)]
    .filter((index) => index !== -1).reduce((left, right) => Math.min(left, right), location.length);
  const authority = location.slice(8, authorityEnd);
  if (!authority || /[@:%\[\]]/.test(authority) || authority !== authority.toLowerCase()) {
    throw new Error("GitHub download redirect is not trusted");
  }
  let url;
  try { url = new URL(location); } catch { throw new Error("GitHub download redirect is not trusted"); }
  const allowed = url.hostname === "objects.githubusercontent.com"
    || url.hostname.endsWith(".githubusercontent.com")
    || url.hostname.endsWith(".blob.core.windows.net");
  if (url.protocol !== "https:" || url.username || url.password || url.port || url.host !== authority
      || url.hash || !allowed) {
    throw new Error("GitHub download redirect is not trusted");
  }
  return location;
}

function allowedCompatibilityDownloadHost(location) {
  const url = new URL(location);
  return url.protocol === "https:" && (
    url.hostname === "objects.githubusercontent.com"
    || url.hostname.endsWith(".githubusercontent.com")
    || url.hostname.endsWith(".blob.core.windows.net")
  );
}

export async function downloadGitHubBytesObserved(url, token, fetchImpl, limit, notBefore = null) {
  if (!Number.isInteger(limit) || limit < 1 || limit > 1_000_000) {
    throw new Error("GitHub download limit is invalid");
  }
  let first;
  try {
    first = await fetchImpl(url, {
      headers: headers(token), redirect: "manual", signal: AbortSignal.timeout(8_000),
    });
  } catch {
    throw new Error("GitHub download initial transport failed");
  }
  let redirectedAt;
  let firstStatus;
  let location;
  let firstBody;
  try {
    const responseHeaders = first?.headers;
    redirectedAt = responseTime(responseHeaders?.get?.("date"));
    firstStatus = first?.status;
    location = responseHeaders?.get?.("location");
    firstBody = first?.body;
  } catch {
    throw new Error("GitHub download redirect primitives are invalid");
  }
  if (firstStatus !== 302 || typeof location !== "string") {
    try { await firstBody?.cancel?.(); } catch { /* static failure below */ }
    throw new Error("GitHub download did not return one trusted redirect");
  }
  const finalUrl = trustedDownloadUrl(location);
  try { await firstBody?.cancel?.(); } catch { throw new Error("GitHub download redirect body is invalid"); }
  let response;
  try {
    response = await fetchImpl(finalUrl, { redirect: "error", signal: AbortSignal.timeout(8_000) });
  } catch {
    throw new Error("GitHub download redirected transport failed");
  }
  const captured = captureBodyResponse(response, "GitHub download response");
  const { observedAt, status, ok } = captured;
  const redirectedAtNs = timestampNanoseconds(redirectedAt);
  const observedAtNs = timestampNanoseconds(observedAt);
  const withinRedirectSkewTolerance = redirectedAtNs !== null && observedAtNs !== null
    && redirectedAtNs - observedAtNs <= REDIRECT_CLOCK_SKEW_TOLERANCE_NS;
  if (status !== 200 || ok !== true
      || !(timestampAtOrBefore(redirectedAt, observedAt) || withinRedirectSkewTolerance)
      || (notBefore !== null && !timestampAtOrBefore(notBefore, redirectedAt))) {
    try { await captured.reader?.cancel(); } catch { /* static failure below */ }
    throw new Error("GitHub download response is invalid");
  }
  const bytes = await readBoundedBody(captured, limit, "GitHub download");
  if (CREDENTIAL.test(bytes.toString("utf8"))) throw new Error("GitHub evidence contains credential-shaped material");
  return { bytes: Buffer.from(bytes), observedAt };
}

export async function downloadGitHubBytes(url, token, fetchImpl, limit) {
  const first = await fetchImpl(url, { headers: headers(token), redirect: "manual", signal: AbortSignal.timeout(8_000) });
  let response = first;
  if ([301, 302, 303, 307, 308].includes(first.status)) {
    const location = first.headers.get("location");
    if (!location || !allowedCompatibilityDownloadHost(location)) throw new Error("GitHub download redirect is not trusted");
    response = await fetchImpl(location, { redirect: "error", signal: AbortSignal.timeout(8_000) });
  }
  if (!response.ok) throw new Error(`GitHub download failed with HTTP ${response.status}`);
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (declared > limit) throw new Error("GitHub download is too large");
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > limit) throw new Error("GitHub download is too large");
  if (CREDENTIAL.test(bytes.toString("utf8"))) throw new Error("GitHub evidence contains credential-shaped material");
  return bytes;
}

export function extractSingleJsonArtifact(zipBytes, expectedName) {
  const entries = new AdmZip(zipBytes).getEntries().filter((entry) => !entry.isDirectory);
  if (entries.length !== 1 || entries[0].entryName !== expectedName || entries[0].header.size > 64_000) {
    throw new Error("GitHub denial artifact archive is invalid");
  }
  const bytes = entries[0].getData();
  if (bytes.length > 64_000 || CREDENTIAL.test(bytes.toString("utf8"))) throw new Error("GitHub denial artifact is unsafe");
  return JSON.parse(bytes.toString("utf8"));
}

function classifyLog(log, hostileId, provider) {
  const value = log.toString("utf8");
  if (hostileId === "H8") {
    if (/(PERMISSION_DENIED|does not have permission|Permission .* denied)/i.test(value)
        && /(run\.services\.update|services update|Cloud Run)/i.test(value)) return "CLOUD_RUN_IAM_DENIED";
  } else if (!value.includes(`federated token for //iam.googleapis.com/${provider}:`)) {
    throw new Error(`${hostileId} log does not name the approved WIF provider`);
  } else if (hostileId === "H7") {
    if (/(audience|allowed audiences)/i.test(value) && /(invalid|rejected|denied|unauthorized_client)/i.test(value)
        && /(google-github-actions\/auth|Security Token Service|STS)/i.test(value)) return "AUDIENCE_DENIED";
  } else if (/credential is rejected by the attribute condition/i.test(value)
      && /(google-github-actions\/auth|Security Token Service|STS)/i.test(value)) {
    return "WIF_CONDITION_DENIED";
  }
  throw new Error(`${hostileId} log does not prove the intended rejection point`);
}

function validateArtifact(value, hostileId, run, expected) {
  const baseKeys = ["environment", "event", "head_sha", "id", "outcome", "ref", "run_attempt", "run_id", "version", "workflow_ref"];
  const optional = hostileId === "H7" ? ["audience"] : hostileId === "H8" ? ["target"] : ["owner_id", "repository_id"];
  if (!value || typeof value !== "object" || Object.keys(value).some((key) => ![...baseKeys, ...optional].includes(key))) {
    throw new Error("GitHub denial artifact fields are invalid");
  }
  const expectedIds = ["H1", "H2"].includes(hostileId) ? new Set(["external", hostileId]) : new Set([hostileId]);
  if (value.version !== 1 || !expectedIds.has(value.id) || value.outcome !== "failure"
      || value.run_id !== String(run.id) || value.run_attempt !== String(run.run_attempt)
      || value.head_sha !== run.head_sha || value.event !== run.event || value.ref !== `refs/heads/${run.head_branch}`
      || value.workflow_ref !== `${expected.owner}/${expected.repository}/${run.path}@${value.ref}`) {
    throw new Error("GitHub denial artifact does not match the run");
  }
  if (hostileId === "H1" && value.owner_id === expected.ownerId) throw new Error("H1 did not use a different owner ID");
  if (hostileId === "H2" && (value.owner_id !== expected.ownerId || value.repository_id === expected.repositoryId)) {
    throw new Error("H2 did not use the intended owner and a different repository ID");
  }
  if (hostileId === "H3" && value.ref !== "refs/heads/keyless-h3") throw new Error("H3 ref is wrong");
  if (hostileId === "H4" && run.path !== ".github/workflows/k0-hostile-wrong-workflow.yml") throw new Error("H4 workflow ref is wrong");
  if (hostileId === "H5" && value.event !== "workflow_dispatch") throw new Error("H5 event is wrong");
  if (hostileId === "H6" && value.environment !== "staging") throw new Error("H6 environment is wrong");
  if (hostileId === "H7" && !value.audience?.includes("/projects/0/")) throw new Error("H7 audience is wrong");
  if (hostileId === "H8" && value.target !== expected.forbiddenService) throw new Error("H8 target is wrong");
  if (hostileId !== "H6" && value.environment !== "production") throw new Error(`${hostileId} environment is wrong`);
}

export async function collectGitHubDenialEvidence({
  owner, repository, runId, hostileId, installationToken, scopeOwnerId, scopeRepositoryId, forbiddenService, provider,
  fetchImpl = fetch,
}) {
  exact(owner, OWNER, "owner");
  exact(repository, REPOSITORY, "repository");
  exact(String(runId), NUMERIC, "run ID");
  if (!Object.hasOwn(JOBS, hostileId)) throw new Error("hostile ID is invalid");
  const token = requireGitHubReadToken(installationToken);
  const ownerId = exact(scopeOwnerId, NUMERIC, "scope owner ID");
  const repositoryId = exact(scopeRepositoryId, NUMERIC, "scope repository ID");
  exact(forbiddenService, SERVICE, "forbidden service");
  exact(provider, PROVIDER, "WIF provider");
  const base = `https://api.github.com/repos/${owner}/${repository}`;
  const firstResponses = await Promise.all([
    fetchGitHubJsonObserved(`${base}/actions/runs/${runId}`, token, fetchImpl),
    fetchGitHubJsonObserved(`${base}/actions/runs/${runId}/jobs?per_page=100`, token, fetchImpl),
    fetchGitHubJsonObserved(`${base}/actions/runs/${runId}/artifacts?per_page=100`, token, fetchImpl),
  ]);
  const [run, jobsResponse, artifactsResponse] = firstResponses.map(({ value }) => value);
  if (String(run?.id) !== String(runId) || run?.status !== "completed" || run?.conclusion !== "success"
      || run?.repository?.full_name !== `${owner}/${repository}` || !exact(run?.head_sha, SHA, "head SHA")) {
    throw new Error("GitHub hostile run is not an authoritative completed success");
  }
  const jobs = boundedGitHubPage(jobsResponse, "jobs").filter(({ name }) => name === JOBS[hostileId]);
  if (jobs.length !== 1 || jobs[0].status !== "completed" || jobs[0].conclusion !== "success"
      || !isGitHubHostedJob(jobs[0])) {
    throw new Error("GitHub hostile job is missing or unsuccessful");
  }
  if (!isRfc3339(run.run_started_at) || !isRfc3339(jobs[0].completed_at)
      || !timestampAtOrBefore(run.run_started_at, jobs[0].completed_at)
      || (jobs[0].started_at !== undefined && (!isRfc3339(jobs[0].started_at)
        || !timestampAtOrBefore(run.run_started_at, jobs[0].started_at)
        || !timestampAtOrBefore(jobs[0].started_at, jobs[0].completed_at)))) {
    throw new Error("GitHub hostile timeline is invalid");
  }
  const requiredName = `Require ${["H1", "H2"].includes(hostileId) ? "external identity" : hostileId} denial`;
  if (jobs[0].steps?.find(({ name }) => name === requiredName)?.conclusion !== "success") {
    throw new Error("GitHub denial assertion did not succeed");
  }
  const artifactName = ["H1", "H2"].includes(hostileId) ? "keyless-external-denial" : `keyless-${hostileId.toLowerCase()}-denial`;
  const artifacts = boundedGitHubPage(artifactsResponse, "artifacts")
    .filter((item) => item.name === artifactName && !item.expired);
  if (artifacts.length !== 1 || !Number.isInteger(artifacts[0].id)) {
    throw new Error("GitHub denial artifact is missing or ambiguous");
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
  const value = extractSingleJsonArtifact(zip, ["H1", "H2"].includes(hostileId) ? "k0-external.json" : `k0-${hostileId}.json`);
  validateArtifact(value, hostileId, run, { owner, repository, ownerId, repositoryId, forbiddenService });
  const category = classifyLog(log, hostileId, provider);
  const apiOwnerId = String(run.repository.owner.id);
  const apiRepositoryId = String(run.repository.id);
  if ((value.owner_id && value.owner_id !== apiOwnerId) || (value.repository_id && value.repository_id !== apiRepositoryId)) {
    throw new Error("GitHub denial artifact repository IDs do not match the API");
  }
  if (!["H1", "H2"].includes(hostileId) && (apiOwnerId !== ownerId || apiRepositoryId !== repositoryId)) {
    throw new Error(`${hostileId} did not run in the scoped repository`);
  }
  const contentResponses = await Promise.all([
    fetchGitHubJsonObserved(`${base}/contents/${run.path}?ref=${run.head_sha}`, token, fetchImpl),
    fetchGitHubJsonObserved(`${base}/contents/demo/release.txt?ref=${run.head_sha}`, token, fetchImpl),
  ]);
  const [workflowContent, releaseContent] = contentResponses.map(({ value }) => value);
  const observations = [...firstResponses, ...downloadResponses, ...contentResponses].map(({ observedAt }) => observedAt);
  if (observations.some((value) => !timestampAtOrBefore(jobs[0].completed_at, value))) {
    throw new Error("GitHub denial evidence occurrence is after collection");
  }
  const observedAt = observations.reduce((latest, value) => timestampAtOrBefore(latest, value) ? value : latest);
  const workflow = githubWorkflowSnapshot(workflowContent);
  const githubRun = {
    run_id: String(run.id), run_attempt: String(run.run_attempt), head_sha: run.head_sha, workflow_path: run.path,
    workflow_ref: value.workflow_ref, owner_id: apiOwnerId, repository_id: apiRepositoryId, event: run.event,
    ref: value.ref, environment: value.environment, conclusion: run.conclusion,
    runner_environment: "github-hosted", started_at: run.run_started_at,
    workflow_blob_sha: workflow.workflow_blob_sha, workflow_sha256: workflow.workflow_sha256,
    actor_id: exact(String(run?.actor?.id), NUMERIC, "run actor ID"),
    release_marker: githubReleaseMarker(releaseContent),
  };
  const logSha256 = createHash("sha256").update(log).digest("hex");
  const clientResult = hostileId === "H8" ? {
    hostile_id: hostileId, run_id: String(run.id), run_attempt: String(run.run_attempt), head_sha: run.head_sha,
    outcome: "DENIED", reached_cloud_run: true, target: forbiddenService,
    denied_at: jobs[0].completed_at, log_sha256: logSha256,
  } : {
    hostile_id: hostileId, run_id: String(run.id), run_attempt: String(run.run_attempt), head_sha: run.head_sha,
    outcome: "DENIED", reached_sts: true, error_category: category, provider,
    denied_at: jobs[0].completed_at, log_sha256: logSha256,
  };
  return { observedAt, githubRun, clientResult };
}
