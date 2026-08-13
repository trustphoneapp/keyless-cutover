import { createHash } from "node:crypto";
import AdmZip from "adm-zip";
import { requireGitHubInstallationToken } from "./github-token.mjs";

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}$/;
const NUMERIC = /^\d+$/;
const SHA = /^[a-f0-9]{40}$/;
const SERVICE = /^[a-z][a-z0-9-]{0,62}$/;
const CREDENTIAL = /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"private_key"\s*:|ya29\.[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35})/;
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

export async function fetchGitHubJson(url, token, fetchImpl) {
  const response = await fetchImpl(url, { headers: headers(token), redirect: "error", signal: AbortSignal.timeout(8_000) });
  const text = await response.text();
  if (text.length > 1_000_000) throw new Error("GitHub API response is too large");
  if (!response.ok) throw new Error(`GitHub API failed with HTTP ${response.status}`);
  return JSON.parse(text);
}

function allowedDownloadHost(location) {
  const url = new URL(location);
  return url.protocol === "https:" && (
    url.hostname === "objects.githubusercontent.com"
    || url.hostname.endsWith(".githubusercontent.com")
    || url.hostname.endsWith(".blob.core.windows.net")
  );
}

export async function downloadGitHubBytes(url, token, fetchImpl, limit) {
  const first = await fetchImpl(url, { headers: headers(token), redirect: "manual", signal: AbortSignal.timeout(8_000) });
  let response = first;
  if ([301, 302, 303, 307, 308].includes(first.status)) {
    const location = first.headers.get("location");
    if (!location || !allowedDownloadHost(location)) throw new Error("GitHub download redirect is not trusted");
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

function classifyLog(log, hostileId) {
  const value = log.toString("utf8");
  if (hostileId === "H8") {
    if (/(PERMISSION_DENIED|does not have permission|Permission .* denied)/i.test(value)
        && /(run\.services\.update|services update|Cloud Run)/i.test(value)) return "CLOUD_RUN_IAM_DENIED";
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
      || value.head_sha !== run.head_sha || value.event !== run.event || value.ref !== `refs/heads/${run.head_branch}`) {
    throw new Error("GitHub denial artifact does not match the run");
  }
  if (hostileId === "H1" && value.owner_id === expected.ownerId) throw new Error("H1 did not use a different owner ID");
  if (hostileId === "H2" && (value.owner_id !== expected.ownerId || value.repository_id === expected.repositoryId)) {
    throw new Error("H2 did not use the intended owner and a different repository ID");
  }
  if (hostileId === "H3" && value.ref !== "refs/heads/keyless-h3") throw new Error("H3 ref is wrong");
  if (hostileId === "H4" && !value.workflow_ref.includes("k0-hostile-wrong-workflow.yml@refs/heads/main")) throw new Error("H4 workflow ref is wrong");
  if (hostileId === "H5" && value.event !== "workflow_dispatch") throw new Error("H5 event is wrong");
  if (hostileId === "H6" && value.environment !== "staging") throw new Error("H6 environment is wrong");
  if (hostileId === "H7" && !value.audience?.includes("/projects/0/")) throw new Error("H7 audience is wrong");
  if (hostileId === "H8" && value.target !== expected.forbiddenService) throw new Error("H8 target is wrong");
  if (hostileId !== "H6" && value.environment !== "production") throw new Error(`${hostileId} environment is wrong`);
}

export async function collectGitHubDenialEvidence({
  owner, repository, runId, hostileId, installationToken, scopeOwnerId, scopeRepositoryId, forbiddenService, fetchImpl = fetch,
}) {
  exact(owner, OWNER, "owner");
  exact(repository, REPOSITORY, "repository");
  exact(String(runId), NUMERIC, "run ID");
  if (!Object.hasOwn(JOBS, hostileId)) throw new Error("hostile ID is invalid");
  const token = requireGitHubInstallationToken(installationToken);
  const ownerId = exact(scopeOwnerId, NUMERIC, "scope owner ID");
  const repositoryId = exact(scopeRepositoryId, NUMERIC, "scope repository ID");
  exact(forbiddenService, SERVICE, "forbidden service");
  const base = `https://api.github.com/repos/${owner}/${repository}`;
  const [run, jobsResponse, artifactsResponse] = await Promise.all([
    fetchGitHubJson(`${base}/actions/runs/${runId}`, token, fetchImpl),
    fetchGitHubJson(`${base}/actions/runs/${runId}/jobs?per_page=100`, token, fetchImpl),
    fetchGitHubJson(`${base}/actions/runs/${runId}/artifacts?per_page=100`, token, fetchImpl),
  ]);
  if (String(run?.id) !== String(runId) || run?.status !== "completed" || run?.conclusion !== "success"
      || run?.repository?.full_name !== `${owner}/${repository}` || !exact(run?.head_sha, SHA, "head SHA")) {
    throw new Error("GitHub hostile run is not an authoritative completed success");
  }
  const jobs = jobsResponse?.jobs?.filter(({ name }) => name === JOBS[hostileId]);
  if (!Array.isArray(jobs) || jobs.length !== 1 || jobs[0].status !== "completed" || jobs[0].conclusion !== "success") {
    throw new Error("GitHub hostile job is missing or unsuccessful");
  }
  const requiredName = `Require ${["H1", "H2"].includes(hostileId) ? "external identity" : hostileId} denial`;
  if (jobs[0].steps?.find(({ name }) => name === requiredName)?.conclusion !== "success") {
    throw new Error("GitHub denial assertion did not succeed");
  }
  const artifactName = ["H1", "H2"].includes(hostileId) ? "keyless-external-denial" : `keyless-${hostileId.toLowerCase()}-denial`;
  const artifacts = artifactsResponse?.artifacts?.filter((item) => item.name === artifactName && !item.expired);
  if (!Array.isArray(artifacts) || artifacts.length !== 1 || !Number.isInteger(artifacts[0].id)) {
    throw new Error("GitHub denial artifact is missing or ambiguous");
  }
  const [zip, log] = await Promise.all([
    downloadGitHubBytes(`${base}/actions/artifacts/${artifacts[0].id}/zip`, token, fetchImpl, 512_000),
    downloadGitHubBytes(`${base}/actions/jobs/${jobs[0].id}/logs`, token, fetchImpl, 1_000_000),
  ]);
  const value = extractSingleJsonArtifact(zip, ["H1", "H2"].includes(hostileId) ? "k0-external.json" : `k0-${hostileId}.json`);
  validateArtifact(value, hostileId, run, { ownerId, repositoryId, forbiddenService });
  const category = classifyLog(log, hostileId);
  const apiOwnerId = String(run.repository.owner.id);
  const apiRepositoryId = String(run.repository.id);
  if ((value.owner_id && value.owner_id !== apiOwnerId) || (value.repository_id && value.repository_id !== apiRepositoryId)) {
    throw new Error("GitHub denial artifact repository IDs do not match the API");
  }
  if (!["H1", "H2"].includes(hostileId) && (apiOwnerId !== ownerId || apiRepositoryId !== repositoryId)) {
    throw new Error(`${hostileId} did not run in the scoped repository`);
  }
  const githubRun = {
    run_id: String(run.id), run_attempt: String(run.run_attempt), head_sha: run.head_sha, workflow_path: run.path,
    workflow_ref: value.workflow_ref, owner_id: apiOwnerId, repository_id: apiRepositoryId, event: run.event,
    ref: value.ref, environment: value.environment, conclusion: run.conclusion,
  };
  const logSha256 = createHash("sha256").update(log).digest("hex");
  const clientResult = hostileId === "H8" ? {
    hostile_id: hostileId, run_id: String(run.id), outcome: "DENIED", reached_cloud_run: true,
    target: forbiddenService, log_sha256: logSha256,
  } : {
    hostile_id: hostileId, run_id: String(run.id), outcome: "DENIED", reached_sts: true,
    error_category: category, log_sha256: logSha256,
  };
  return { githubRun, clientResult };
}
