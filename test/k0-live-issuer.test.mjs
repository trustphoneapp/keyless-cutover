import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, link, lstat, mkdir, mkdtemp, readFile, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import test from "node:test";
import AdmZip from "adm-zip";

import { canonicalJson } from "../src/evidence-artifact.mjs";
import { issueK0Live, parseK0LiveRecollectionPlan } from "../src/k0-live-issuer.mjs";
import { createK0PreDisableArchive } from "../src/k0-predisable-archive.mjs";
import { verifyK0Bundle } from "../src/k0-bundle.mjs";
import { createKmsSigningRequest } from "../src/k0-kms.mjs";
import { verifyK0Receipt } from "../src/k0-receipt.mjs";
import {
  evidenceByKind,
  refreshCheckpointReceipt,
  refreshFinalCredentialScan,
  validK0BundleInput,
  validWifAuditLog,
} from "./fixtures/k0-bundle.mjs";

const token = `ghs_${"t".repeat(36)}`;
const owner = "owner";
const repository = "repo";
const receiptPath = "docs/evidence/K0_CHECKPOINT_EXAMPLE.json";
const archivePath = "docs/evidence/K0_PREDISABLE_ARCHIVE_EXAMPLE.json";
const workflowBytes = await readFile(new URL("../.github/workflows/k0-deploy.yml", import.meta.url));
const legacyWorkflowBytes = await readFile(new URL("../.github/workflows/k0-legacy-auth-check.yml", import.meta.url));

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function blobSha(bytes) {
  return createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
}

function workflowIdentity(bytes) {
  return { workflow_blob_sha: blobSha(bytes), workflow_sha256: digest(bytes) };
}

function content(bytes, path) {
  return { encoding: "base64", content: bytes.toString("base64"), sha: blobSha(bytes), ...(path ? { path } : {}) };
}

function response(value, date, { status = 200, headers = {} } = {}) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
  return new Response(bytes, { status, headers: { ...(date ? { date } : {}), ...headers } });
}

function plan(overrides = {}) {
  const value = {
    version: 1,
    domain: "KEYLESS_K0_LIVE_RECOLLECTION_PLAN_V1",
    github: {
      owner,
      repository,
      checkpoint_pull_number: 12,
      receipt_path: receiptPath,
      archive_path: archivePath,
      legacy_run_id: "3001",
      wif2_run_id: "3002",
    },
    gcp: { disable_actor: "key-operator@example.com" },
    kms: {
      key_version: "projects/example-project/locations/global/keyRings/keyless/cryptoKeys/k0/cryptoKeyVersions/1",
    },
  };
  return Buffer.from(canonicalJson({ ...value, ...overrides }));
}

async function archiveFixture() {
  const input = validK0BundleInput();
  const deploy = workflowIdentity(workflowBytes);
  const legacy = workflowIdentity(legacyWorkflowBytes);
  input.manifest.cutover.workflow_blob_sha = deploy.workflow_blob_sha;
  input.manifest.cutover.workflow_sha256 = deploy.workflow_sha256;
  for (const id of input.manifest.cutover.source_ids) {
    const envelope = input.evidence.find((item) => item.id === id);
    if (["GITHUB_RUN", "GITHUB_PULL_REQUEST"].includes(envelope?.kind)) {
      envelope.data.workflow_blob_sha = deploy.workflow_blob_sha;
      envelope.data.workflow_sha256 = deploy.workflow_sha256;
    }
  }
  for (const hostile of input.manifest.hostile_tests.filter(({ id }) => ["H3", "H5", "H6", "H7", "H8"].includes(id))) {
    const run = input.evidence.find((item) => hostile.source_ids.includes(item.id) && item.kind === "GITHUB_RUN");
    run.data.workflow_blob_sha = deploy.workflow_blob_sha;
    run.data.workflow_sha256 = deploy.workflow_sha256;
  }
  input.manifest.approved_workflows.legacy.workflow_blob_sha = legacy.workflow_blob_sha;
  input.manifest.approved_workflows.legacy.workflow_sha256 = legacy.workflow_sha256;
  const legacyApproval = input.evidence.find(({ id }) => id === input.manifest.approved_workflows.legacy.source_id);
  legacyApproval.data.workflow_blob_sha = legacy.workflow_blob_sha;
  legacyApproval.data.workflow_sha256 = legacy.workflow_sha256;
  refreshCheckpointReceipt(input);
  refreshFinalCredentialScan(input);

  const preIds = new Set([
    ...input.manifest.legacy_baseline.source_ids,
    ...input.manifest.proof.source_ids,
    ...input.manifest.cutover.source_ids,
    ...input.manifest.wif.source_ids,
    ...Object.values(input.manifest.approved_workflows).map(({ source_id: sourceId }) => sourceId),
    ...input.manifest.hostile_tests.flatMap(({ source_ids: sourceIds }) => sourceIds),
  ]);
  const fragment = Object.fromEntries([
    "scope", "revisions", "approved_workflows", "legacy_baseline", "proof", "cutover", "wif", "hostile_tests",
  ].map((field) => [field, structuredClone(input.manifest[field])]));
  const evidence = input.evidence.filter(({ id }) => preIds.has(id)).map(({ public_url: _url, ...entry }) => entry);
  const artifacts = new Map(evidence.map((envelope) => {
    const artifact = canonicalJson({ version: 1, id: envelope.id, kind: envelope.kind, locator: envelope.locator,
      observed_at: envelope.observed_at, data: envelope.data });
    return [envelope.id, Buffer.from(artifact)];
  }));
  const archive = await createK0PreDisableArchive({
    version: 1,
    transaction_id: "example-transaction-1",
    nonce: "example-public-nonce-0001",
    scope: structuredClone(fragment.scope),
    fragment,
    evidence: evidence.map(({ data: _data, ...entry }) => ({
      ...entry,
      sha256: digest(artifacts.get(entry.id)),
    })),
  }, artifacts);
  return {
    archiveBytes: archive.archiveBytes,
    checkpointReceiptBytes: Buffer.from(evidenceByKind(input, "GITHUB_EVIDENCE_CHECKPOINT").data.receipt.bytes_base64, "base64"),
    fragment,
  };
}

function legacyZip(scope) {
  const artifact = {
    version: 1,
    id: "legacy-after-disable",
    outcome: "failure",
    key_id: scope.key_id,
    run_id: "3001",
    run_attempt: "1",
    head_sha: "e".repeat(40),
    workflow_ref: `${owner}/${repository}/.github/workflows/k0-legacy-auth-check.yml@refs/heads/main`,
    event: "workflow_dispatch",
    ref: "refs/heads/main",
    environment: "production",
    fresh_runner: true,
    fresh_online_request: true,
  };
  const zip = new AdmZip();
  zip.addFile("k0-legacy-after-disable.json", Buffer.from(JSON.stringify(artifact)));
  return zip.toBuffer();
}

function authenticatedFixture({ archiveBytes, checkpointReceiptBytes, fragment }, mutate = () => {}) {
  const scope = fragment.scope;
  const values = {
    protection: {
      required_status_checks: { strict: true, checks: [{ context: "test", app_id: 15368 }] },
      required_pull_request_reviews: {
        required_approving_review_count: 1,
        dismiss_stale_reviews: true,
        require_last_push_approval: true,
      },
      enforce_admins: { enabled: true },
      required_linear_history: { enabled: true },
    },
    checkpointPull: {
      number: 12,
      state: "closed",
      merged: true,
      merged_at: "2026-08-13T12:09:05Z",
      merge_commit_sha: "c".repeat(40),
      head: { sha: "b".repeat(40) },
      user: { id: 20 },
      base: { ref: "main", repo: { id: 2, full_name: `${owner}/${repository}`, owner: { id: 1 } } },
    },
    checkpointReviews: [{
      state: "APPROVED", commit_id: "b".repeat(40), submitted_at: "2026-08-13T12:09:01Z", user: { id: 21 },
    }],
    checkpointRuns: { total_count: 1, workflow_runs: [{
      id: 4001, run_attempt: 1, path: ".github/workflows/ci.yml", head_sha: "c".repeat(40),
      event: "push", head_branch: "main", status: "completed", conclusion: "success",
      run_started_at: "2026-08-13T12:09:10Z", updated_at: "2026-08-13T12:09:45Z",
      repository: { id: 2, full_name: `${owner}/${repository}`, owner: { id: 1 } },
    }] },
    checkpointChecks: { total_count: 1, check_runs: [{
      name: "test", head_sha: "c".repeat(40), app: { id: 15368, slug: "github-actions" },
      status: "completed", conclusion: "success",
      started_at: "2026-08-13T12:09:15Z", completed_at: "2026-08-13T12:09:40Z",
      details_url: `https://github.com/${owner}/${repository}/actions/runs/4001/job/5001`,
    }] },
    key: {
      name: `projects/-/serviceAccounts/${scope.service_account_email}/keys/${scope.key_id}`,
      keyType: "USER_MANAGED", keyAlgorithm: ["KEY", "ALG", "RSA", "2048"].join("_"), disabled: true,
      validAfterTime: "2026-08-13T10:00:00Z",
    },
    account: {
      name: `projects/${scope.project_id}/serviceAccounts/${scope.service_account_email}`,
      projectId: scope.project_id, email: scope.service_account_email,
      uniqueId: scope.service_account_unique_id, disabled: false,
    },
    disableAudit: { entries: [{
      insertId: "audit-1", timestamp: "2026-08-13T12:10:00Z",
      protoPayload: {
        methodName: "google.iam.admin.v1.DisableServiceAccountKey",
        resourceName: `projects/-/serviceAccounts/${scope.service_account_unique_id}/keys/${scope.key_id}`,
        authenticationInfo: { principalEmail: "key-operator@example.com" }, status: {},
      },
    }] },
    legacyRun: {
      id: 3001, run_attempt: 1, status: "completed", conclusion: "success", head_sha: "e".repeat(40),
      head_branch: "main", path: ".github/workflows/k0-legacy-auth-check.yml", event: "workflow_dispatch",
      run_started_at: "2026-08-13T12:11:00Z", actor: { id: 10 },
      repository: { id: 2, full_name: `${owner}/${repository}`, owner: { id: 1 } },
    },
    legacyJobs: { total_count: 1, jobs: [{
      id: 3011, name: "fresh-legacy-auth", status: "completed", conclusion: "success",
      runner_group_name: "GitHub Actions", labels: ["ubuntu-latest"],
      started_at: "2026-08-13T12:11:05Z", completed_at: "2026-08-13T12:11:30Z",
      steps: [{ name: "Require fresh legacy denial", conclusion: "success" }],
    }] },
    legacyArtifacts: { total_count: 1, artifacts: [{
      id: 3012, name: "keyless-legacy-after-disable", expired: false,
    }] },
    wifRun: {
      id: 3002, run_attempt: 1, status: "completed", conclusion: "success", head_sha: "f".repeat(40),
      head_branch: "main", path: ".github/workflows/k0-deploy.yml", event: "push",
      run_started_at: "2026-08-13T12:13:00Z", actor: { id: 10 },
      repository: { id: 2, full_name: `${owner}/${repository}`, owner: { id: 1 } },
    },
    wifJobs: { total_count: 1, jobs: [{
      id: 3021, name: "deploy", status: "completed", conclusion: "success",
      runner_group_name: "GitHub Actions", labels: ["ubuntu-latest"],
      started_at: "2026-08-13T12:13:05Z", completed_at: "2026-08-13T12:13:40Z",
      steps: [
        { name: "Authenticate through WIF", conclusion: "success" },
        { name: "Deploy through WIF", conclusion: "success" },
      ],
    }] },
    wifApprovals: [{ state: "approved", user: { id: 11 }, environments: [{ name: "production" }] }],
    wifRevision: {
      name: `projects/${scope.project_id}/locations/${scope.region}/services/${scope.allowed_service}/revisions/${fragment.revisions.wif_2}`,
      createTime: "2026-08-13T12:13:45Z",
      conditions: [{ type: "Ready", state: "CONDITION_SUCCEEDED" }],
      containers: [{
        image: `us-docker.pkg.dev/example/repo/app@sha256:${"a".repeat(64)}`,
        env: [{ name: "RELEASE", value: "wif-2" }],
      }],
    },
    wifAudit: JSON.parse(validWifAuditLog(fragment)),
  };
  const forbiddenSource = fragment.revisions.forbidden_after_hostile_source_id;
  const archive = JSON.parse(archiveBytes.toString("utf8"));
  const forbiddenArtifact = JSON.parse(Buffer.from(
    archive.artifacts.find(({ id }) => id === forbiddenSource).bytes_base64, "base64",
  ).toString("utf8"));
  values.forbiddenRevision = {
    name: `projects/${scope.project_id}/locations/${scope.region}/services/${scope.forbidden_service}/revisions/${fragment.revisions.forbidden_after}`,
    createTime: forbiddenArtifact.data.create_time,
    conditions: [{ type: "Ready", state: "CONDITION_SUCCEEDED" }],
    containers: [{
      image: `us-docker.pkg.dev/example/repo/forbidden@${forbiddenArtifact.data.image_digest}`,
      env: [{ name: "RELEASE", value: forbiddenArtifact.data.release_marker }],
    }],
  };
  mutate(values);

  const requests = [];
  const transcript = [];
  let authCalls = 0;
  const googleAuth = {
    async getClient() {
      authCalls += 1;
      return { getRequestHeaders: async () => ({ authorization: "Bearer fake-google-access" }) };
    },
  };
  const checkpointDate = "Thu, 13 Aug 2026 12:18:00 GMT";
  const route = async (url, options = {}) => {
    const path = String(url);
    if (path.endsWith("/branches/main/protection")) return response(values.protection, checkpointDate);
    if (path.endsWith("/pulls/12")) return response(values.checkpointPull, checkpointDate);
    if (path.includes("/pulls/12/reviews")) return response(values.checkpointReviews, checkpointDate);
    if (path.includes(`/contents/${receiptPath}?ref=`)) return response(content(checkpointReceiptBytes, receiptPath), checkpointDate);
    if (path.includes(`/contents/${archivePath}?ref=`)) return response(content(archiveBytes, archivePath), checkpointDate);
    if (path.includes("/actions/runs?branch=main")) return response(values.checkpointRuns, checkpointDate);
    if (path.includes("/commits/") && path.includes("/check-runs")) return response(values.checkpointChecks, checkpointDate);

    if (path.includes(`/serviceAccounts/${encodeURIComponent(scope.service_account_email)}/keys/${scope.key_id}`)) {
      return response(values.key, "Thu, 13 Aug 2026 12:10:30 GMT");
    }
    if (path.includes("iam.googleapis.com/v1/projects/-/serviceAccounts/") && !path.includes("/keys/")) {
      return response(values.account, "Thu, 13 Aug 2026 12:10:30 GMT");
    }
    if (path === "https://logging.googleapis.com/v2/entries:list") {
      const body = JSON.parse(options.body);
      return body.filter.includes("DisableServiceAccountKey")
        ? response(values.disableAudit, "Thu, 13 Aug 2026 12:10:31 GMT")
        : response(values.wifAudit, "Thu, 13 Aug 2026 12:14:00 GMT");
    }

    if (path.endsWith("/actions/runs/3001")) return response(values.legacyRun, "Thu, 13 Aug 2026 12:12:00 GMT");
    if (path.includes("/actions/runs/3001/jobs")) return response(values.legacyJobs, "Thu, 13 Aug 2026 12:12:00 GMT");
    if (path.includes("/actions/runs/3001/artifacts")) return response(values.legacyArtifacts, "Thu, 13 Aug 2026 12:12:00 GMT");
    if (path.endsWith("/actions/artifacts/3012/zip")) return response("", "Thu, 13 Aug 2026 12:12:00 GMT", {
      status: 302, headers: { location: "https://objects.githubusercontent.com/legacy.zip?sig=example" },
    });
    if (path.endsWith("/actions/jobs/3011/logs")) return response("", "Thu, 13 Aug 2026 12:12:00 GMT", {
      status: 302, headers: { location: "https://objects.githubusercontent.com/legacy.txt?sig=example" },
    });
    if (path.includes("objects.githubusercontent.com/legacy.zip")) {
      return response(legacyZip(scope), "Thu, 13 Aug 2026 12:12:00 GMT");
    }
    if (path.includes("objects.githubusercontent.com/legacy.txt")) {
      return response("gcloud problem refreshing auth: invalid_grant Invalid JWT Signature", "Thu, 13 Aug 2026 12:12:00 GMT");
    }
    if (path.includes("/contents/.github/workflows/k0-legacy-auth-check.yml")) {
      return response(content(legacyWorkflowBytes), "Thu, 13 Aug 2026 12:12:00 GMT");
    }

    if (path.endsWith("/actions/runs/3002")) return response(values.wifRun, "Thu, 13 Aug 2026 12:14:00 GMT");
    if (path.includes("/actions/runs/3002/jobs")) return response(values.wifJobs, "Thu, 13 Aug 2026 12:14:00 GMT");
    if (path.endsWith("/actions/runs/3002/approvals")) return response(values.wifApprovals, "Thu, 13 Aug 2026 12:14:00 GMT");
    if (path.includes("/contents/.github/workflows/k0-deploy.yml")) {
      return response(content(workflowBytes), "Thu, 13 Aug 2026 12:14:00 GMT");
    }
    if (path.includes("/contents/demo/release.txt")) {
      return response({ encoding: "base64", content: Buffer.from("wif-2\n").toString("base64"), sha: "a0edac1ca398917d44f52651419451d90f8d67ac" },
        "Thu, 13 Aug 2026 12:14:00 GMT");
    }
    if (path.includes(`/services/${scope.allowed_service}/revisions/${fragment.revisions.wif_2}`)) {
      return response(values.wifRevision, "Thu, 13 Aug 2026 12:14:00 GMT");
    }
    if (path.includes(`/services/${scope.forbidden_service}/revisions/${fragment.revisions.forbidden_after}`)) {
      return response(values.forbiddenRevision, "Thu, 13 Aug 2026 12:15:00 GMT");
    }
    throw new Error(`unexpected request: ${path}`);
  };
  const fetchImpl = async (url, options = {}) => {
    const request = { url: String(url), method: options.method ?? "GET", body: options.body };
    requests.push(request);
    const reply = await route(url, options);
    const clone = reply.clone();
    transcript.push({
      url: request.url,
      method: request.method,
      request_body: request.body ?? null,
      status: clone.status,
      headers: Object.fromEntries(clone.headers.entries()),
      body_base64: Buffer.from(await clone.arrayBuffer()).toString("base64"),
    });
    return reply;
  };
  return { values, requests, transcript, googleAuth, fetchImpl, authCalls: () => authCalls };
}

const archive = await archiveFixture();

test("live issuer recollects the fixed authenticated transaction and remains pending", async (t) => {
  const fixture = authenticatedFixture(archive);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fixture.fetchImpl;
  t.after(() => { globalThis.fetch = originalFetch; });
  const planBytes = plan();
  const pending = issueK0Live(planBytes, { installationToken: token, googleAuth: fixture.googleAuth });
  planBytes.fill(0x20);
  const result = await pending;
  assert.equal(result.status, "K0_VERIFIED_RECEIPT_PENDING");
  assert.equal(result.authorization, "RECOLLECTION_REQUIRED");
  assert.equal(result.release_ready, false);
  assert.equal(result.receipt.receipt.authorization, "RECOLLECTION_REQUIRED");
  assert.equal(result.receipt.receipt.release_ready, false);
  await verifyK0Bundle(result.bundle);
  await verifyK0Receipt({ receiptBytes: result.receipt.receiptBytes, ...result.bundle });
  assert.equal(result.kmsRequest.name,
    "projects/example-project/locations/global/keyRings/keyless/cryptoKeys/k0/cryptoKeyVersions/1");
  assert.equal(result.kmsRequest.digest.sha256,
    createHash("sha256").update(result.receipt.receiptBytes).digest("base64"));
  assert.equal(fixture.authCalls(), 6);
  assert.equal(fixture.requests.length, 28);
  assert.deepEqual(fixture.requests.map(({ url }) => new URL(url).pathname), [
    `/repos/${owner}/${repository}/branches/main/protection`,
    `/repos/${owner}/${repository}/pulls/12`,
    `/repos/${owner}/${repository}/pulls/12/reviews`,
    `/repos/${owner}/${repository}/contents/${receiptPath}`,
    `/repos/${owner}/${repository}/contents/${receiptPath}`,
    `/repos/${owner}/${repository}/contents/${archivePath}`,
    `/repos/${owner}/${repository}/contents/${archivePath}`,
    `/repos/${owner}/${repository}/actions/runs`,
    `/repos/${owner}/${repository}/commits/${"c".repeat(40)}/check-runs`,
    `/v1/projects/-/serviceAccounts/${scopeEmail(archive.fragment.scope)}/keys/${archive.fragment.scope.key_id}`,
    `/v1/projects/-/serviceAccounts/${scopeEmail(archive.fragment.scope)}`,
    "/v2/entries:list",
    `/repos/${owner}/${repository}/actions/runs/3001`,
    `/repos/${owner}/${repository}/actions/runs/3001/jobs`,
    `/repos/${owner}/${repository}/actions/runs/3001/artifacts`,
    `/repos/${owner}/${repository}/actions/artifacts/3012/zip`,
    `/repos/${owner}/${repository}/actions/jobs/3011/logs`,
    "/legacy.zip", "/legacy.txt",
    `/repos/${owner}/${repository}/contents/.github/workflows/k0-legacy-auth-check.yml`,
    `/repos/${owner}/${repository}/actions/runs/3002`,
    `/repos/${owner}/${repository}/actions/runs/3002/jobs`,
    `/repos/${owner}/${repository}/actions/runs/3002/approvals`,
    `/repos/${owner}/${repository}/contents/.github/workflows/k0-deploy.yml`,
    `/repos/${owner}/${repository}/contents/demo/release.txt`,
    `/v2/projects/${archive.fragment.scope.project_id}/locations/${archive.fragment.scope.region}/services/${archive.fragment.scope.allowed_service}/revisions/${archive.fragment.revisions.wif_2}`,
    "/v2/entries:list",
    `/v2/projects/${archive.fragment.scope.project_id}/locations/${archive.fragment.scope.region}/services/${archive.fragment.scope.forbidden_service}/revisions/${archive.fragment.revisions.forbidden_after}`,
  ]);
  assert.equal(fixture.requests.filter(({ method }) => method === "POST").length, 2);
  assert(fixture.requests.filter(({ method }) => method === "POST")
    .every(({ url }) => url === "https://logging.googleapis.com/v2/entries:list"));
  assert(fixture.requests.every(({ method }) => !["DELETE", "PATCH", "PUT"].includes(method)));
  const rendered = Buffer.concat([
    result.bundle.manifestBytes, result.receipt.receiptBytes, result.kmsRequestBytes,
  ]).toString("utf8");
  assert.equal(rendered.includes(token), false);
  assert.equal(rendered.includes("fake-google-access"), false);
  assert.equal(rendered.includes("FINAL"), false);
});

function scopeEmail(scope) {
  return encodeURIComponent(scope.service_account_email);
}

test("live issuer output is deterministic for the same authenticated snapshots", async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  const first = authenticatedFixture(archive);
  globalThis.fetch = first.fetchImpl;
  const left = await issueK0Live(plan(), { installationToken: token, googleAuth: first.googleAuth });
  const second = authenticatedFixture(archive);
  globalThis.fetch = second.fetchImpl;
  const right = await issueK0Live(plan(), { installationToken: token, googleAuth: second.googleAuth });
  assert(left.bundle.manifestBytes.equals(right.bundle.manifestBytes));
  assert(left.receipt.receiptBytes.equals(right.receipt.receiptBytes));
  assert(left.kmsRequestBytes.equals(right.kmsRequestBytes));
});

test("live issuer rejects plan and credential authority before authentication", async () => {
  let authCalls = 0;
  const googleAuth = { getClient: async () => { authCalls += 1; throw new Error("must not authenticate"); } };
  const base = JSON.parse(plan().toString("utf8"));
  const invalid = [
    Buffer.from(` ${canonicalJson(base)}`),
    Buffer.from(JSON.stringify(base)),
    Buffer.from(canonicalJson({ ...base, unknown: true })),
    Buffer.from(canonicalJson({ ...base, github: { ...base.github, owner: "owner/path" } })),
    Buffer.from(canonicalJson({ ...base, github: { ...base.github, archive_path: "docs/evidence/../bad.json" } })),
    Buffer.from(canonicalJson({ ...base, github: { ...base.github, legacy_run_id: "latest" } })),
    Buffer.from(canonicalJson({
      ...base,
      github: { ...base.github, legacy_run_id: base.github.wif2_run_id },
    })),
    Buffer.from(canonicalJson({ ...base, gcp: { disable_actor: "actor@example.com\" OR true" } })),
    Buffer.from(canonicalJson({ ...base, kms: { key_version: "projects/example/cryptoKeyVersions/latest" } })),
    Buffer.from(canonicalJson({ ...base, github: { ...base.github, token: `ghs_${"x".repeat(36)}` } })),
    Buffer.alloc(32 * 1024 + 1),
  ];
  for (const bytes of invalid) {
    assert.throws(() => issueK0Live(bytes, { installationToken: token, googleAuth }));
  }
  assert.throws(() => parseK0LiveRecollectionPlan("not bytes"));
  assert.throws(
    () => parseK0LiveRecollectionPlan(Buffer.from(plan().toString("utf8").replace('"version":1', '"version":1,"version":1'))),
    /duplicate JSON key/,
  );
  const accessor = Object.defineProperty({ installationToken: token, googleAuth }, "installationToken", {
    enumerable: true, get: () => token,
  });
  assert.throws(() => issueK0Live(plan(), accessor));
  assert.throws(() => issueK0Live(plan(), new Proxy({ installationToken: token, googleAuth }, {})));
  assert.throws(() => issueK0Live(plan(), { installationToken: token, googleAuth: new Proxy(googleAuth, {}) }));
  assert.equal(authCalls, 0);
});

test("live issuer fails closed on authenticated key, workflow, audit, and revision drift", async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  const attacks = [
    (values) => { values.key.disabled = false; },
    (values) => { values.disableAudit.entries[0].protoPayload.authenticationInfo.principalEmail = "other@example.com"; },
    (values) => { values.legacyJobs.total_count = 2; },
    (values) => { values.wifRun.path = ".github/workflows/other.yml"; },
    (values) => { values.wifRevision.createTime = "2026-08-13T12:12:59Z"; },
    (values) => { values.wifAudit.nextPageToken = "more"; },
    (values) => { values.forbiddenRevision.containers[0].env[0].value = "changed"; },
  ];
  for (const mutate of attacks) {
    const fixture = authenticatedFixture(archive, mutate);
    globalThis.fetch = fixture.fetchImpl;
    await assert.rejects(() => issueK0Live(plan(), { installationToken: token, googleAuth: fixture.googleAuth }));
    assert(fixture.requests.every(({ method }) => !["DELETE", "PATCH", "PUT"].includes(method)));
  }
});

function runCli(args, env = {}, cwd) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(process.execPath, [new URL("../bin/k0-live-issuer.mjs", import.meta.url).pathname, ...args], {
      cwd, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, 5_000);
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", rejectRun);
    child.on("close", (code) => {
      clearTimeout(timeout);
      resolveRun({
        code, timedOut, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
  });
}

async function waitForPath(path) {
  for (let attempt = 0; attempt < 300; attempt += 1) {
    try {
      await lstat(path);
      return;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 5));
  }
  throw new Error("test output barrier was not reached");
}

function assertCliFailed(value) {
  assert.equal(value.timedOut, false);
  assert.notEqual(value.code, 0);
  assert.equal(value.stdout, "");
  assert.equal(value.stderr, "K0 live issuer command failed\n");
  assert.equal(value.stderr.includes(token), false);
}

async function verifyPendingOutputFile(path) {
  const bytes = await readFile(path);
  const value = JSON.parse(bytes);
  assert(bytes.equals(Buffer.from(canonicalJson(value), "utf8")));
  assert.equal(value.version, 1);
  assert.equal(value.domain, "KEYLESS_K0_LIVE_PENDING_OUTPUT_V1");
  assert.deepEqual(Object.keys(value).sort(), [
    "artifacts", "domain", "kms_request", "manifest_bytes_base64", "receipt_bytes_base64", "version",
  ]);
  assert.equal("status" in value, false);
  assert.equal("authorization" in value, false);
  assert.equal("release_ready" in value, false);
  const manifestBytes = Buffer.from(value.manifest_bytes_base64, "base64");
  const manifest = JSON.parse(manifestBytes);
  const artifacts = new Map(value.artifacts.map(({ id, bytes_base64: encoded }) => [
    id, Buffer.from(encoded, "base64"),
  ]));
  assert.deepEqual([...artifacts.keys()], [...artifacts.keys()].toSorted());
  const receiptBytes = Buffer.from(value.receipt_bytes_base64, "base64");
  await verifyK0Bundle({ manifest, artifacts });
  await verifyK0Receipt({ receiptBytes, manifest, manifestBytes, artifacts });
  assert.deepEqual(value.kms_request, createKmsSigningRequest(receiptBytes, value.kms_request.name));
  assert.deepEqual(Object.keys(value.kms_request).sort(), ["digest", "name"]);
  assert.deepEqual(Object.keys(value.kms_request.digest), ["sha256"]);
  assert.equal("release_ready" in value.kms_request, false);
  assert.equal("authorization" in value.kms_request, false);
  assert.equal(JSON.parse(receiptBytes).authorization, "RECOLLECTION_REQUIRED");
  assert.equal(JSON.parse(receiptBytes).release_ready, false);
  return bytes;
}

test("live issuer pending verifier source rejects duplicate JSON keys", async () => {
  const source = await readFile(new URL("../bin/k0-live-issuer.mjs", import.meta.url), "utf8");
  assert.match(source, /rejectDuplicateJsonKeys\(text\)/);
  assert.match(source, /pending output contains duplicate JSON keys/);
  assert.match(source, /output manifest contains duplicate JSON keys/);
});

test("pending issuer envelope and kms_request refuse promotion fields", async () => {
  const { assembleK0Bundle } = await import("../src/k0-bundle.mjs");
  const { createK0Receipt } = await import("../src/k0-receipt.mjs");
  const { createKmsSigningRequest } = await import("../src/k0-kms.mjs");
  const { validK0BundleInput } = await import("./fixtures/k0-bundle.mjs");
  const bundle = await assembleK0Bundle(validK0BundleInput());
  const { receipt, receiptBytes } = await createK0Receipt(bundle);
  const keyVersion = "projects/example-project/locations/global/keyRings/keyless/cryptoKeys/k0-receipt/cryptoKeyVersions/1";
  const kmsRequest = createKmsSigningRequest(receiptBytes, keyVersion);
  const artifacts = [...bundle.artifacts]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([id, bytes]) => ({ id, bytes_base64: bytes.toString("base64") }));
  const valid = {
    version: 1,
    domain: "KEYLESS_K0_LIVE_PENDING_OUTPUT_V1",
    manifest_bytes_base64: bundle.manifestBytes.toString("base64"),
    artifacts,
    receipt_bytes_base64: receiptBytes.toString("base64"),
    kms_request: kmsRequest,
  };
  assert.deepEqual(Object.keys(valid).sort(), [
    "artifacts", "domain", "kms_request", "manifest_bytes_base64", "receipt_bytes_base64", "version",
  ]);
  assert.deepEqual(Object.keys(valid.kms_request).sort(), ["digest", "name"]);
  assert.equal(receipt.authorization, "RECOLLECTION_REQUIRED");
  assert.equal(receipt.release_ready, false);

  for (const [label, mutate] of [
    ["top-level release_ready", (value) => { value.release_ready = true; }],
    ["top-level AUTHORIZED", (value) => { value.authorization = "AUTHORIZED"; }],
    ["top-level GO", (value) => { value.status = "GO"; }],
    ["kms release_ready", (value) => { value.kms_request = { ...kmsRequest, release_ready: true }; }],
    ["kms AUTHORIZED", (value) => { value.kms_request = { ...kmsRequest, authorization: "AUTHORIZED" }; }],
    ["kms extra field", (value) => { value.kms_request = { ...kmsRequest, extra: true }; }],
  ]) {
    const value = structuredClone(valid);
    mutate(value);
    const promoted = "release_ready" in value || "authorization" in value || "status" in value
      || Object.keys(value.kms_request).length !== 2
      || "release_ready" in value.kms_request
      || "authorization" in value.kms_request
      || "extra" in value.kms_request;
    assert.equal(promoted, true, label);
  }
});

test("live issuer CLI accepts only one safe basename and atomically rejects occupied targets", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "k0-live-issuer-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const validPlan = join(directory, "plan.json");
  const badPlan = join(directory, "bad.json");
  const planLink = join(directory, "plan-link.json");
  await writeFile(validPlan, plan());
  await writeFile(badPlan, "{}");
  await symlink(validPlan, planLink);
  const authMarker = join(directory, "unexpected-auth");
  const guardPreload = join(directory, "guard-preload.mjs");
  await writeFile(guardPreload, `
import { writeFileSync } from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(${JSON.stringify(join(process.cwd(), "package.json"))});
const { GoogleAuth } = require("google-auth-library");
const mark = () => { writeFileSync(${JSON.stringify(authMarker)}, "unexpected", { flag: "wx" }); };
GoogleAuth.prototype.getClient = async function getClient() { mark(); throw new Error("unexpected auth"); };
globalThis.fetch = async () => { mark(); throw new Error("unexpected fetch"); };
`);
  const guardEnv = {
    KEYLESS_GITHUB_TOKEN: token,
    NODE_OPTIONS: `--import=${pathToFileURL(guardPreload).href}`,
  };
  const escapeName = `../k0-live-issuer-escape-${process.pid}.json`;
  const escapePath = join(directory, escapeName);
  const absoluteOutput = join(directory, "absolute-output.json");

  for (const output of [
    escapeName, absoluteOutput, "nested/output.json", "nested\\output.json", ".json", "..json",
    "é.json", "bad?.json", "upper.JSON", `${"a".repeat(125)}.json`,
  ]) {
    assertCliFailed(await runCli([validPlan, output], guardEnv, directory));
  }
  await assert.rejects(() => lstat(escapePath));
  await assert.rejects(() => lstat(absoluteOutput));
  assertCliFailed(await runCli([validPlan, "extra.json", "extra"], guardEnv, directory));
  await assert.rejects(() => lstat(join(directory, "extra.json")));
  assertCliFailed(await runCli([planLink, "linked-plan.json"], guardEnv, directory));
  await assert.rejects(() => lstat(join(directory, "linked-plan.json")));

  const invalidResidue = join(directory, "invalid-plan.json");
  assertCliFailed(await runCli([badPlan, "invalid-plan.json"], guardEnv, directory));
  await assert.rejects(() => lstat(invalidResidue));

  await writeFile(join(directory, "existing.json"), "occupied");
  await symlink(join(directory, "existing.json"), join(directory, "linked-output.json"));
  assertCliFailed(await runCli([validPlan, "existing.json"], guardEnv, directory));
  assertCliFailed(await runCli([validPlan, "linked-output.json"], guardEnv, directory));
  assert.equal(await readFile(join(directory, "existing.json"), "utf8"), "occupied");

  const fifo = join(directory, "output-fifo.json");
  const madeFifo = await new Promise((resolveFifo) => {
    const child = spawn("mkfifo", [fifo]);
    child.on("error", () => resolveFifo(false));
    child.on("close", (code) => resolveFifo(code === 0));
  });
  if (madeFifo) {
    assertCliFailed(await runCli([validPlan, "output-fifo.json"], guardEnv, directory));
    assert((await lstat(fifo)).isFIFO());
  }
  await assert.rejects(() => lstat(authMarker));
});

test("live issuer CLI writes and rereads one exact private pending output", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "k0-live-issuer-success-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const fixture = authenticatedFixture(archive);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fixture.fetchImpl;
  try {
    await issueK0Live(plan(), { installationToken: token, googleAuth: fixture.googleAuth });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(fixture.transcript.length, 28);
  const transcriptPath = join(directory, "transcript.json");
  const preloadPath = join(directory, "preload.mjs");
  await writeFile(transcriptPath, JSON.stringify(fixture.transcript));
  await writeFile(preloadPath, `
import { readFileSync } from "node:fs";
import { open, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
const require = createRequire(${JSON.stringify(join(process.cwd(), "package.json"))});
const { GoogleAuth } = require("google-auth-library");
const entries = JSON.parse(readFileSync(${JSON.stringify(transcriptPath)}, "utf8"));
let index = 0;
let fileHandlePrototype;
if (["KEYLESS_K0_TEST_FAIL_SYNC", "KEYLESS_K0_TEST_FAIL_WRITE", "KEYLESS_K0_TEST_FAIL_READ",
  "KEYLESS_K0_TEST_FAIL_OUTPUT_CLOSE", "KEYLESS_K0_TEST_FAIL_TRUNCATE",
  "KEYLESS_K0_TEST_FAIL_FIRST_CHMOD", "KEYLESS_K0_TEST_FAIL_MARKER_WRITE"]
  .some((name) => process.env[name] !== undefined)) {
  const probePath = join(process.env.KEYLESS_K0_TEST_BARRIER_DIR, "handle-probe");
  const probe = await open(probePath, "wx", 0o600);
  fileHandlePrototype = Object.getPrototypeOf(probe);
  await probe.close();
  await rm(probePath);
}
if (process.env.KEYLESS_K0_TEST_FAIL_SYNC === "1") {
  const realSync = fileHandlePrototype.sync;
  let syncFailed = false;
  fileHandlePrototype.sync = async function sync() {
    if (!syncFailed) {
      syncFailed = true;
      throw new Error("injected sync failure");
    }
    return realSync.call(this);
  };
}
if (process.env.KEYLESS_K0_TEST_FAIL_WRITE === "1") {
  const realWrite = fileHandlePrototype.write;
  let writeFailed = false;
  fileHandlePrototype.write = async function write(...args) {
    if (!writeFailed) {
      writeFailed = true;
      throw new Error("injected write failure");
    }
    return realWrite.apply(this, args);
  };
}
if (process.env.KEYLESS_K0_TEST_FAIL_READ === "1") {
  const realRead = fileHandlePrototype.read;
  let readFailed = false;
  fileHandlePrototype.read = async function read(...args) {
    if (!readFailed) {
      readFailed = true;
      throw new Error("injected read failure");
    }
    return realRead.apply(this, args);
  };
}
if (process.env.KEYLESS_K0_TEST_FAIL_TRUNCATE) {
  const realTruncate = fileHandlePrototype.truncate;
  const failureCount = Number(process.env.KEYLESS_K0_TEST_FAIL_TRUNCATE);
  let truncateCount = 0;
  fileHandlePrototype.truncate = async function truncate(...args) {
    truncateCount += 1;
    if (truncateCount <= failureCount) throw new Error("injected truncate failure");
    return realTruncate.apply(this, args);
  };
}
if (process.env.KEYLESS_K0_TEST_FAIL_FIRST_CHMOD === "1") {
  const realChmod = fileHandlePrototype.chmod;
  let chmodFailed = false;
  fileHandlePrototype.chmod = async function chmod(...args) {
    if (!chmodFailed) {
      chmodFailed = true;
      throw new Error("injected chmod failure");
    }
    return realChmod.apply(this, args);
  };
}
if (process.env.KEYLESS_K0_TEST_FAIL_MARKER_WRITE === "1") {
  const realWrite = fileHandlePrototype.write;
  let markerWriteFailed = false;
  fileHandlePrototype.write = async function write(...args) {
    if (!markerWriteFailed && Buffer.isBuffer(args[0]) && args[0].length === 1 && args[0][0] === 0xff
        && args[1] === 0 && args[2] === 1 && args[3] === 0) {
      markerWriteFailed = true;
      throw new Error("injected marker write failure");
    }
    return realWrite.apply(this, args);
  };
}
if (process.env.KEYLESS_K0_TEST_FAIL_OUTPUT_CLOSE === "1") {
  const realClose = fileHandlePrototype.close;
  let closeCount = 0;
  fileHandlePrototype.close = async function close() {
    closeCount += 1;
    if (closeCount === 2) {
      await realClose.call(this);
      throw new Error("injected committed close failure");
    }
    return realClose.call(this);
  };
}
GoogleAuth.prototype.getClient = async function getClient() {
  return { getRequestHeaders: async () => ({ authorization: "Bearer fake-google-access" }) };
};
globalThis.fetch = async (url, options = {}) => {
  const entry = entries[index++];
  if (!entry || entry.url !== String(url) || entry.method !== (options.method ?? "GET")
      || entry.request_body !== (options.body ?? null)) throw new Error("unexpected authenticated request");
  return new Response(Buffer.from(entry.body_base64, "base64"), {
    status: entry.status,
    headers: entry.headers,
  });
};
if (process.env.KEYLESS_K0_TEST_BARRIER_DIR) {
  globalThis.__KEYLESS_K0_INTERNAL_OUTPUT_BARRIER__ = async (stage, basename) => {
    if (stage !== (process.env.KEYLESS_K0_TEST_BARRIER_STAGE ?? "after-open")) return;
    const barrier = process.env.KEYLESS_K0_TEST_BARRIER_DIR;
    await writeFile(join(barrier, "ready"), basename, { flag: "wx" });
    if (process.env.KEYLESS_K0_TEST_BARRIER_FAIL === "1") throw new Error("injected output failure");
    for (;;) {
      try {
        await readFile(join(barrier, "continue"));
        return;
      } catch (error) {
        if (error?.code !== "ENOENT") throw new Error("output barrier failed");
      }
      await new Promise((resolveWait) => setTimeout(resolveWait, 5));
    }
  };
}
process.on("exit", () => { if (index !== entries.length) process.exitCode = 91; });
`);
  const planPath = join(directory, "plan.json");
  const outputName = "pending-output.json";
  const output = join(directory, outputName);
  await writeFile(planPath, plan());
  const result = await runCli([planPath, outputName], {
    KEYLESS_GITHUB_TOKEN: token,
    NODE_OPTIONS: `--import=${pathToFileURL(preloadPath).href}`,
  }, directory);
  assert.equal(result.timedOut, false);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /^K0_VERIFIED_RECEIPT_PENDING manifest_sha256=[a-f0-9]{64} receipt_sha256=[a-f0-9]{64}\n$/);
  assert.equal(result.stdout.includes(token), false);
  assert.equal(result.stderr, "");
  assert.equal((await stat(output)).mode & 0o777, 0o600);
  const exactOutput = await verifyPendingOutputFile(output);
  assert.equal(exactOutput.includes(Buffer.from(token)), false);

  const closeCwd = join(directory, "close-cwd");
  const closeBarrier = join(directory, "close-barrier");
  await mkdir(closeCwd);
  await mkdir(closeBarrier);
  const closeResult = await runCli([planPath, "close.json"], {
    KEYLESS_GITHUB_TOKEN: token,
    NODE_OPTIONS: `--import=${pathToFileURL(preloadPath).href}`,
    KEYLESS_K0_TEST_BARRIER_DIR: closeBarrier,
    KEYLESS_K0_TEST_BARRIER_STAGE: "unused",
    KEYLESS_K0_TEST_FAIL_OUTPUT_CLOSE: "1",
  }, closeCwd);
  assert.equal(closeResult.code, 0, closeResult.stderr);
  assert.match(closeResult.stdout,
    /^K0_VERIFIED_RECEIPT_PENDING manifest_sha256=[a-f0-9]{64} receipt_sha256=[a-f0-9]{64}\n$/);
  assert.equal(closeResult.stderr, "");
  await verifyPendingOutputFile(join(closeCwd, "close.json"));

  const racedOutputName = "raced-output.json";
  const racedOutput = join(directory, racedOutputName);
  const childEnv = {
    KEYLESS_GITHUB_TOKEN: token,
    NODE_OPTIONS: `--import=${pathToFileURL(preloadPath).href}`,
  };
  const raced = await Promise.all([
    runCli([planPath, racedOutputName], childEnv, directory),
    runCli([planPath, racedOutputName], childEnv, directory),
  ]);
  assert.equal(raced.filter(({ code }) => code === 0).length, 1);
  assert.equal(raced.filter(({ code }) => code !== 0).length, 1);
  assert(raced.every(({ timedOut }) => timedOut === false));
  await verifyPendingOutputFile(racedOutput);
  assert.equal(raced.find(({ code }) => code !== 0).stderr, "K0 live issuer command failed\n");

  const raceEnv = (barrier, stage, fail = false) => ({
    KEYLESS_GITHUB_TOKEN: token,
    NODE_OPTIONS: `--import=${pathToFileURL(preloadPath).href}`,
    KEYLESS_K0_TEST_BARRIER_DIR: barrier,
    KEYLESS_K0_TEST_BARRIER_STAGE: stage,
    ...(fail ? { KEYLESS_K0_TEST_BARRIER_FAIL: "1" } : {}),
  });

  const anchoredOld = join(directory, "anchored-old");
  const anchoredNew = join(directory, "anchored-new");
  const anchoredBarrier = join(directory, "anchored-barrier");
  await mkdir(anchoredOld);
  await mkdir(anchoredBarrier);
  const anchoredRun = runCli([planPath, "anchored.json"], raceEnv(anchoredBarrier, "after-open"), anchoredOld);
  await waitForPath(join(anchoredBarrier, "ready"));
  await rename(anchoredOld, anchoredNew);
  await writeFile(join(anchoredBarrier, "continue"), "go", { flag: "wx" });
  const anchoredResult = await anchoredRun;
  assert.equal(anchoredResult.code, 0, anchoredResult.stderr);
  await verifyPendingOutputFile(join(anchoredNew, "anchored.json"));

  const replaceCwd = join(directory, "replace-cwd");
  const replaceBarrier = join(directory, "replace-barrier");
  const replaceResidue = join(replaceCwd, "replace-residue.json");
  const replaceMarker = join(directory, "replace-marker.json");
  await mkdir(replaceCwd);
  await mkdir(replaceBarrier);
  await writeFile(replaceMarker, "");
  const replaceRun = runCli([planPath, "replace.json"], raceEnv(replaceBarrier, "after-open"), replaceCwd);
  await waitForPath(join(replaceBarrier, "ready"));
  await rename(join(replaceCwd, "replace.json"), replaceResidue);
  await symlink(replaceMarker, join(replaceCwd, "replace.json"));
  await writeFile(join(replaceBarrier, "continue"), "go", { flag: "wx" });
  assertCliFailed(await replaceRun);
  assert.equal((await stat(replaceMarker)).size, 0);
  assert.equal((await stat(replaceResidue)).size, 0);
  assert.equal((await stat(replaceResidue)).mode & 0o777, 0o600);

  for (const [name, stage] of [
    ["partial", "after-partial-write"],
    ["write", "after-write"],
    ["sync-boundary", "before-sync"],
  ]) {
    const failureCwd = join(directory, `${name}-cwd`);
    const failureBarrier = join(directory, `${name}-barrier`);
    await mkdir(failureCwd);
    await mkdir(failureBarrier);
    const failureResult = await runCli([planPath, `${name}.json`],
      raceEnv(failureBarrier, stage, true), failureCwd);
    assertCliFailed(failureResult);
    const residuePath = join(failureCwd, `${name}.json`);
    const residue = await readFile(residuePath);
    assert.equal(residue.length, 0);
    assert.equal((await stat(residuePath)).mode & 0o777, 0o600);
    assert.equal(residue.includes(Buffer.from(token)), false);
  }

  for (const operation of ["WRITE", "SYNC", "READ"]) {
    const operationName = operation.toLowerCase();
    const operationCwd = join(directory, `actual-${operationName}-cwd`);
    const operationBarrier = join(directory, `actual-${operationName}-barrier`);
    await mkdir(operationCwd);
    await mkdir(operationBarrier);
    const operationResult = await runCli([planPath, `${operationName}.json`], {
      ...raceEnv(operationBarrier, "unused"),
      [`KEYLESS_K0_TEST_FAIL_${operation}`]: "1",
    }, operationCwd);
    assertCliFailed(operationResult);
    const operationPath = join(operationCwd, `${operationName}.json`);
    assert.equal((await stat(operationPath)).size, 0);
    assert.equal((await stat(operationPath)).mode & 0o777, 0o600);
  }

  for (const truncateFailures of [1, 2]) {
    const truncateCwd = join(directory, `truncate-${truncateFailures}-cwd`);
    const truncateBarrier = join(directory, `truncate-${truncateFailures}-barrier`);
    const truncatePath = join(truncateCwd, `truncate-${truncateFailures}.json`);
    await mkdir(truncateCwd);
    await mkdir(truncateBarrier);
    const truncateResult = await runCli([planPath, `truncate-${truncateFailures}.json`], {
      ...raceEnv(truncateBarrier, "after-write", true),
      KEYLESS_K0_TEST_FAIL_TRUNCATE: String(truncateFailures),
    }, truncateCwd);
    assertCliFailed(truncateResult);
    const residue = await readFile(truncatePath);
    assert.equal(residue[0], 0xff);
    assert.equal(residue.length, truncateFailures === 1 ? 1 : exactOutput.length);
    assert.equal((await stat(truncatePath)).mode & 0o777, 0o600);
    assert.equal(residue.includes(Buffer.from(token)), false);
    await assert.rejects(() => verifyPendingOutputFile(truncatePath));
  }

  const markerCwd = join(directory, "marker-write-cwd");
  const markerBarrier = join(directory, "marker-write-barrier");
  await mkdir(markerCwd);
  await mkdir(markerBarrier);
  const markerResult = await runCli([planPath, "marker-write.json"], {
    ...raceEnv(markerBarrier, "after-write", true),
    KEYLESS_K0_TEST_FAIL_TRUNCATE: "1",
    KEYLESS_K0_TEST_FAIL_MARKER_WRITE: "1",
  }, markerCwd);
  assertCliFailed(markerResult);
  assert.equal((await stat(join(markerCwd, "marker-write.json"))).size, 0);
  assert.equal((await stat(join(markerCwd, "marker-write.json"))).mode & 0o777, 0o600);

  const chmodRetryCwd = join(directory, "chmod-retry-cwd");
  const chmodRetryBarrier = join(directory, "chmod-retry-barrier");
  const chmodRetryPath = join(chmodRetryCwd, "chmod-retry.json");
  await mkdir(chmodRetryCwd);
  await mkdir(chmodRetryBarrier);
  const chmodRetryRun = runCli([planPath, "chmod-retry.json"], {
    ...raceEnv(chmodRetryBarrier, "final-barrier"),
    KEYLESS_K0_TEST_FAIL_FIRST_CHMOD: "1",
  }, chmodRetryCwd);
  await waitForPath(join(chmodRetryBarrier, "ready"));
  await chmod(chmodRetryPath, 0o644);
  await writeFile(join(chmodRetryBarrier, "continue"), "go", { flag: "wx" });
  assertCliFailed(await chmodRetryRun);
  assert.equal((await stat(chmodRetryPath)).size, 0);
  assert.equal((await stat(chmodRetryPath)).mode & 0o777, 0o600);

  for (const attack of ["append", "corrupt", "chmod", "hardlink"]) {
    const attackCwd = join(directory, `${attack}-cwd`);
    const attackBarrier = join(directory, `${attack}-barrier`);
    const attackPath = join(attackCwd, `${attack}.json`);
    const hardlinkPath = join(directory, `${attack}-alias.json`);
    await mkdir(attackCwd);
    await mkdir(attackBarrier);
    const attackRun = runCli([planPath, `${attack}.json`], raceEnv(attackBarrier, "final-barrier"), attackCwd);
    await waitForPath(join(attackBarrier, "ready"));
    if (attack === "append") await writeFile(attackPath, "x", { flag: "a" });
    if (attack === "corrupt") {
      const changed = await readFile(attackPath);
      changed[Math.floor(changed.length / 2)] ^= 1;
      await writeFile(attackPath, changed);
    }
    if (attack === "chmod") await chmod(attackPath, 0o644);
    if (attack === "hardlink") await link(attackPath, hardlinkPath);
    await writeFile(join(attackBarrier, "continue"), "go", { flag: "wx" });
    assertCliFailed(await attackRun);
    const residue = await readFile(attackPath);
    assert.equal(residue.length, 0);
    assert.equal((await stat(attackPath)).mode & 0o777, 0o600);
    assert.equal(residue.includes(Buffer.from(token)), false);
    if (attack === "hardlink") {
      assert.equal((await stat(hardlinkPath)).size, 0);
      assert.equal((await stat(hardlinkPath)).mode & 0o777, 0o600);
    }
  }

  const finalCwd = join(directory, "final-cwd");
  const finalBarrier = join(directory, "final-barrier");
  const finalResidue = join(finalCwd, "final-residue.json");
  const finalMarker = join(directory, "final-marker.json");
  await mkdir(finalCwd);
  await mkdir(finalBarrier);
  await writeFile(finalMarker, "");
  const finalRun = runCli([planPath, "final.json"], raceEnv(finalBarrier, "final-barrier"), finalCwd);
  await waitForPath(join(finalBarrier, "ready"));
  await rename(join(finalCwd, "final.json"), finalResidue);
  await symlink(finalMarker, join(finalCwd, "final.json"));
  await writeFile(join(finalBarrier, "continue"), "go", { flag: "wx" });
  assertCliFailed(await finalRun);
  assert.equal((await stat(finalMarker)).size, 0);
  assert.equal((await stat(finalResidue)).size, 0);
  assert.equal((await stat(finalResidue)).mode & 0o777, 0o600);
});
