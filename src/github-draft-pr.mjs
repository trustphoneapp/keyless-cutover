import { createHash } from "node:crypto";

import { requireGitHubInstallationToken } from "./github-token.mjs";
import { applyCutoverPlan } from "./workflow-cutover.mjs";

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}$/;
const NUMERIC = /^\d+$/;
const SHA = /^[a-f0-9]{40}$/;
const MIGRATION = /^[a-z0-9][a-z0-9-]{0,39}$/;
const MAX_RESPONSE = 512_000;

function exact(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function decodeContent(value) {
  if (value?.encoding !== "base64" || typeof value.content !== "string" || !exact(value.sha, SHA, "workflow blob SHA")) {
    throw new Error("GitHub workflow content is invalid");
  }
  const decoded = Buffer.from(value.content.replace(/\s/g, ""), "base64").toString("utf8");
  if (!decoded || Buffer.byteLength(decoded) > 64 * 1024) throw new Error("GitHub workflow content size is invalid");
  return decoded;
}

function client({ token, fetchImpl }) {
  const credential = requireGitHubInstallationToken(token);
  return async (method, url, body, allowed = [200, 201]) => {
    const response = await fetchImpl(url, {
      method,
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${credential}`,
        "content-type": "application/json",
        "x-github-api-version": "2022-11-28",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(8_000),
    });
    const text = await response.text();
    if (text.length > MAX_RESPONSE) throw new Error("GitHub response is too large");
    const value = text ? JSON.parse(text) : null;
    if (!allowed.includes(response.status)) {
      const error = new Error(`GitHub API ${method} failed with HTTP ${response.status}`);
      error.status = response.status;
      throw error;
    }
    if (response.status === 404) return null;
    return value;
  };
}

export async function openDraftCutoverPr({
  owner,
  repository,
  installationToken,
  migrationId,
  approvedOwnerId,
  approvedRepositoryId,
  approvedBaseSha,
  approvedCutoverPlan,
  replacementWorkflow,
  fetchImpl = fetch,
}) {
  exact(owner, OWNER, "owner");
  exact(repository, REPOSITORY, "repository");
  exact(migrationId, MIGRATION, "migration ID");
  exact(approvedOwnerId, NUMERIC, "approved owner ID");
  exact(approvedRepositoryId, NUMERIC, "approved repository ID");
  exact(approvedBaseSha, SHA, "approved base SHA");
  if (typeof replacementWorkflow !== "string") throw new Error("replacement workflow is invalid");
  const api = client({ token: installationToken, fetchImpl });
  const base = `https://api.github.com/repos/${owner}/${repository}`;
  const repo = await api("GET", base);
  if (String(repo?.id) !== approvedRepositoryId || String(repo?.owner?.id) !== approvedOwnerId
      || repo?.default_branch !== "main" || repo?.full_name !== `${owner}/${repository}`) {
    throw new Error("live repository identity does not match approval");
  }
  const main = await api("GET", `${base}/git/ref/heads/main`);
  if (main?.object?.type !== "commit" || main.object.sha !== approvedBaseSha) {
    throw new Error("main moved after approval");
  }
  const workflowPath = approvedCutoverPlan?.workflow_path;
  const currentContent = await api("GET", `${base}/contents/${workflowPath}?ref=${approvedBaseSha}`);
  const current = decodeContent(currentContent);
  const replacement = applyCutoverPlan(current, replacementWorkflow, approvedCutoverPlan);
  const branch = `keyless/${migrationId}`;
  const marker = `<!-- keyless-migration:${migrationId} plan:${approvedCutoverPlan.plan_digest} -->`;
  const pullsUrl = `${base}/pulls?state=open&head=${encodeURIComponent(`${owner}:${branch}`)}&base=main`;
  const existing = await api("GET", pullsUrl);
  if (!Array.isArray(existing)) throw new Error("GitHub PR search response is invalid");
  if (existing.length > 1) throw new Error("multiple draft PRs exist for this migration");
  if (existing.length === 1) {
    const branchContent = decodeContent(await api("GET", `${base}/contents/${workflowPath}?ref=${encodeURIComponent(branch)}`));
    if (digest(branchContent) !== approvedCutoverPlan.replacement_sha256
        || existing[0]?.draft !== true || !existing[0]?.body?.includes(marker)) {
      throw new Error("existing migration PR does not match the approved plan");
    }
    return { number: existing[0].number, url: existing[0].html_url, reused: true };
  }
  const branchRefUrl = `${base}/git/ref/${encodeURIComponent(`heads/${branch}`)}`;
  const branchRef = await api("GET", branchRefUrl, undefined, [200, 404]);
  let commitSha;
  if (!branchRef) {
    await api("POST", `${base}/git/refs`, { ref: `refs/heads/${branch}`, sha: approvedBaseSha });
  } else if (branchRef?.object?.type !== "commit" || !exact(branchRef?.object?.sha, SHA, "migration branch SHA")) {
    throw new Error("existing migration branch is invalid");
  }
  if (!branchRef || branchRef.object.sha === approvedBaseSha) {
    const commit = await api("PUT", `${base}/contents/${workflowPath}`, {
      message: `keyless: migrate ${workflowPath} to WIF`,
      content: Buffer.from(replacement).toString("base64"),
      sha: currentContent.sha,
      branch,
    });
    commitSha = exact(commit?.commit?.sha, SHA, "cutover commit SHA");
  } else {
    const branchContent = decodeContent(await api("GET", `${base}/contents/${workflowPath}?ref=${encodeURIComponent(branch)}`));
    if (digest(branchContent) !== approvedCutoverPlan.replacement_sha256) {
      throw new Error("existing migration branch does not match the approved plan");
    }
    commitSha = branchRef.object.sha;
  }
  const pull = await api("POST", `${base}/pulls`, {
    title: "Migrate GitHub Actions deployment to Google WIF",
    head: branch,
    base: "main",
    draft: true,
    body: `${marker}\n\nDeterministically compiled cutover. Human review and merge required.\n\nPlan digest: \`${approvedCutoverPlan.plan_digest}\``,
  });
  if (!Number.isInteger(pull?.number) || pull?.draft !== true || typeof pull?.html_url !== "string"
      || pull?.merged === true || pull?.state === "closed" || pull?.auto_merge != null) {
    throw new Error("GitHub did not return a draft PR");
  }
  return { number: pull.number, url: pull.html_url, commit_sha: commitSha, reused: false };
}
