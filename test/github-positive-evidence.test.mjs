import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../src/evidence-artifact.mjs";
import {
  collectGitHubEvidenceCheckpoint,
  collectGitHubSuccessfulDeploy,
  collectGitHubWorkflowApproval,
} from "../src/github-positive-evidence.mjs";
import { assembleK0Bundle } from "../src/k0-bundle.mjs";
import { createK0PreDisableArchive, verifyK0PreDisableArchive } from "../src/k0-predisable-archive.mjs";
import {
  evidenceByKind,
  refreshCheckpointReceipt,
  refreshFinalCredentialScan,
  validK0BundleInput,
} from "./fixtures/k0-bundle.mjs";
import { validPreDisableArchiveInput } from "./support/k0-predisable.mjs";

const token = `ghs_${"t".repeat(36)}`;
const workflowPath = ".github/workflows/k0-deploy.yml";
const workflow = "name: approved deploy\n";
const headSha = "a".repeat(40);
const mergeSha = "b".repeat(40);
const archivePath = "docs/evidence/K0_PREDISABLE_ARCHIVE_EXAMPLE.json";
const archiveInput = await validPreDisableArchiveInput();
const checkpointArchive = await createK0PreDisableArchive(archiveInput.plan, archiveInput.artifacts);
const checkpointArchiveBlob = createHash("sha1")
  .update(`blob ${checkpointArchive.archiveBytes.length}\0`).update(checkpointArchive.archiveBytes).digest("hex");

function response(value) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { date: "Thu, 13 Aug 2026 12:20:00 GMT" },
  });
}

function checkpointResponse(value, { link = "", date = "Thu, 13 Aug 2026 12:18:00 GMT" } = {}) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { date, ...(link ? { link } : {}) },
  });
}

function replaceContent(value, bytes) {
  value.content = bytes.toString("base64");
  value.sha = createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
}

function changedArchive(mutator) {
  const archive = structuredClone(checkpointArchive.archive);
  mutator(archive);
  return Buffer.from(canonicalJson(archive));
}

function changedReceipt(mutator) {
  const input = validK0BundleInput();
  const receipt = JSON.parse(Buffer.from(
    evidenceByKind(input, "GITHUB_EVIDENCE_CHECKPOINT").data.receipt.bytes_base64,
    "base64",
  ));
  mutator(receipt);
  return Buffer.from(canonicalJson(receipt));
}

function checkpointFixture({ mutate = () => {}, nextPage = false } = {}) {
  const input = validK0BundleInput();
  const expected = evidenceByKind(input, "GITHUB_EVIDENCE_CHECKPOINT").data;
  return async (url) => {
    let kind;
    let value;
    if (url.endsWith("/branches/main/protection")) {
      kind = "protection";
      value = {
        required_status_checks: { strict: true, checks: [{ context: "test", app_id: 15368 }] },
        required_pull_request_reviews: {
          required_approving_review_count: 1,
          dismiss_stale_reviews: true,
          require_last_push_approval: true,
        },
        enforce_admins: { enabled: true },
        required_linear_history: { enabled: true },
      };
    } else if (url.endsWith("/pulls/12")) {
      kind = "pull";
      value = {
        number: 12,
        state: "closed",
        merged: true,
        merged_at: expected.pull.merged_at,
        merge_commit_sha: expected.pull.merge_sha,
        head: { sha: expected.pull.head_sha },
        base: { ref: "main", repo: { id: 2, full_name: "owner/repo", owner: { id: 1 } } },
        user: { id: 20 },
      };
    } else if (url.includes("/pulls/12/reviews")) {
      kind = "reviews";
      value = [{
        state: "APPROVED",
        commit_id: expected.pull.head_sha,
        submitted_at: expected.pull.reviewed_at,
        user: { id: 21 },
      }];
    } else if (url.includes(`/contents/${archivePath}`)) {
      kind = "archive";
      value = {
        encoding: "base64",
        content: checkpointArchive.archiveBytes.toString("base64"),
        sha: checkpointArchiveBlob,
        path: archivePath,
      };
    } else if (url.includes("/contents/docs/evidence/")) {
      kind = "receipt";
      value = {
        encoding: "base64",
        content: expected.receipt.bytes_base64,
        sha: expected.receipt.blob_sha,
        path: expected.receipt.path,
      };
    } else if (url.includes("/actions/runs?")) {
      kind = "runs";
      value = { total_count: 1, workflow_runs: [{
        id: 4001,
        run_attempt: 1,
        head_sha: expected.pull.merge_sha,
        path: ".github/workflows/ci.yml",
        event: "push",
        head_branch: "main",
        status: "completed",
        conclusion: "success",
        run_started_at: expected.run.started_at,
        updated_at: expected.run.completed_at,
        repository: { id: 2, full_name: "owner/repo", owner: { id: 1 } },
      }] };
    } else if (url.includes("/check-runs")) {
      kind = "checks";
      value = { total_count: 1, check_runs: [{
        name: "test",
        head_sha: expected.pull.merge_sha,
        app: { id: 15368, slug: "github-actions" },
        status: "completed",
        conclusion: "success",
        started_at: expected.check.started_at,
        completed_at: expected.check.completed_at,
        details_url: expected.check.details_url,
      }] };
    } else {
      throw new Error(`unexpected URL ${url}`);
    }
    mutate(kind, value, url);
    return checkpointResponse(value, { link: nextPage && kind === "reviews" ? "<https://api.github.com/page=2>; rel=\"next\"" : "" });
  };
}

function fixture({
  selfReview = false,
  wrongCommit = false,
  failedAuth = false,
  runId = "1501",
  runHeadSha = headSha,
  runStartedAt = "2026-08-13T11:30:00Z",
  releaseMarker = "wif-1",
} = {}) {
  return async (url) => {
    if (url.endsWith("/pulls/11")) return response({
      number: 11,
      state: "closed",
      merged: true,
      merged_at: "2026-08-13T11:00:00Z",
      merge_commit_sha: mergeSha,
      head: { sha: headSha },
      base: { ref: "main", repo: { id: 2, full_name: "owner/repo", owner: { id: 1 } } },
      user: { id: 10 },
    });
    if (url.includes("/pulls/11/reviews")) return response([{
      state: "APPROVED",
      commit_id: wrongCommit ? "c".repeat(40) : headSha,
      submitted_at: "2026-08-13T10:59:00Z",
      user: { id: selfReview ? 10 : 11 },
    }]);
    if (url.endsWith(`/actions/runs/${runId}`)) return response({
      id: Number(runId),
      run_attempt: 1,
      status: "completed",
      conclusion: "success",
      path: workflowPath,
      event: "push",
      head_branch: "main",
      head_sha: runHeadSha,
      run_started_at: runStartedAt,
      actor: { id: 10 },
      repository: { id: 2, full_name: "owner/repo", owner: { id: 1 } },
    });
    if (url.includes(`/actions/runs/${runId}/jobs`)) return response({ total_count: 1, jobs: [{
      name: "deploy",
      status: "completed",
      conclusion: "success",
      runner_group_name: "GitHub Actions",
      labels: ["ubuntu-latest"],
      started_at: runStartedAt,
      completed_at: runStartedAt,
      steps: [
        { name: "Authenticate through WIF", conclusion: failedAuth ? "failure" : "success" },
        { name: "Deploy through WIF", conclusion: "success" },
      ],
    }] });
    if (url.endsWith(`/actions/runs/${runId}/approvals`)) return response([{
      state: "approved",
      user: { id: selfReview ? 10 : 11 },
      environments: [{ name: "production" }],
    }]);
    if (url.includes("/contents/demo/release.txt")) return response({
      encoding: "base64",
      content: Buffer.from(`${releaseMarker}\n`).toString("base64"),
    });
    if (url.includes("/contents/")) return response({
      encoding: "base64",
      content: Buffer.from(workflow).toString("base64"),
      sha: "c".repeat(40),
    });
    throw new Error(`unexpected URL ${url}`);
  };
}

function collectCheckpoint(fetchImpl) {
  return collectGitHubEvidenceCheckpoint({
    owner: "owner",
    repository: "repo",
    pullNumber: 12,
    receiptPath: "docs/evidence/K0_CHECKPOINT_EXAMPLE.json",
    archivePath,
    installationToken: token,
    fetchImpl,
  });
}

const checkpointBoundaryMarker = "CHECKPOINT_BOUNDARY_MARKER Authorization https://example.invalid/?token=unit BODY_MARKER";

async function rejectsCheckpointWithoutDisclosure(fetchImpl) {
  let failure;
  try {
    await collectCheckpoint(fetchImpl);
  } catch (error) {
    failure = error;
  }
  assert.equal(failure instanceof Error, true);
  assert.equal(typeof failure.message, "string");
  for (const fragment of [checkpointBoundaryMarker, "CHECKPOINT_BOUNDARY_MARKER", "Authorization",
    "example.invalid", "BODY_MARKER", token]) {
    assert.equal(failure.message.includes(fragment), false);
  }
}

function checkpointBoundaryHeaders(get = (name) => name === "date" ? "Thu, 13 Aug 2026 12:18:00 GMT" : null) {
  return { get };
}

function checkpointBoundaryResponse(reader, overrides = {}) {
  return {
    status: 200,
    ok: true,
    headers: checkpointBoundaryHeaders(),
    body: { getReader: () => reader },
    ...overrides,
  };
}

function checkpointBoundaryFetch(factory) {
  const base = checkpointFixture();
  return (url, options) => url.endsWith("/branches/main/protection") ? factory(url, options) : base(url);
}

test("GitHub collectors derive reviewed workflow bytes and a successful deploy run from API state", async () => {
  const approval = await collectGitHubWorkflowApproval({
    owner: "owner", repository: "repo", pullNumber: 11, workflowPath,
    installationToken: token, fetchImpl: fixture(),
  });
  assert.equal(approval.head_sha, headSha);
  assert.equal(approval.reviewer_id, "11");
  assert.equal(approval.workflow_sha256, createHash("sha256").update(workflow).digest("hex"));

  const collected = await collectGitHubSuccessfulDeploy({
    owner: "owner", repository: "repo", runId: "1501", workflowPath, environment: "production",
    installationToken: token, fetchImpl: fixture(),
  });
  const run = collected.githubRun;
  assert.equal(run.run_id, "1501");
  assert.equal(run.release_marker, "wif-1");
  assert.equal(run.workflow_sha256, approval.workflow_sha256);
  assert.equal(collected.environmentReview.reviewer_id, "11");
  assert.equal(collected.observedAt, "2026-08-13T12:20:00Z");
});

test("GitHub collectors reject self-review, wrong reviewed commit, and failed WIF auth", async () => {
  const approvalInput = {
    owner: "owner", repository: "repo", pullNumber: 11, workflowPath, installationToken: token,
  };
  await assert.rejects(collectGitHubWorkflowApproval({ ...approvalInput, fetchImpl: fixture({ selfReview: true }) }), /approval/);
  await assert.rejects(collectGitHubWorkflowApproval({ ...approvalInput, fetchImpl: fixture({ wrongCommit: true }) }), /approval/);
  await assert.rejects(collectGitHubSuccessfulDeploy({
    owner: "owner", repository: "repo", runId: "1501", workflowPath, environment: "production",
    installationToken: token, fetchImpl: fixture({ failedAuth: true }),
  }), /deploy job/);
});

test("successful deploy collector rejects observations before the completed job", async () => {
  const fetchImpl = fixture();
  await assert.rejects(() => collectGitHubSuccessfulDeploy({
    owner: "owner", repository: "repo", runId: "1501", workflowPath, environment: "production",
    installationToken: token,
    fetchImpl: async (url, options) => {
      const original = await fetchImpl(url, options);
      if (!url.includes("/contents/")) return original;
      return new Response(await original.arrayBuffer(), {
        status: original.status,
        headers: { date: "Thu, 13 Aug 2026 11:29:00 GMT" },
      });
    },
  }), /after collection/);
});

test("authenticated GitHub deploy evidence for wif-1 and wif-2 feeds the bundle", async () => {
  const input = validK0BundleInput();
  const approval = await collectGitHubWorkflowApproval({
    owner: "owner", repository: "repo", pullNumber: 11, workflowPath,
    installationToken: token, fetchImpl: fixture(),
  });
  const wif1 = await collectGitHubSuccessfulDeploy({
    owner: "owner", repository: "repo", runId: "1501", workflowPath, environment: "production",
    installationToken: token, fetchImpl: fixture(),
  });
  const wif2Head = "d".repeat(40);
  const wif2 = await collectGitHubSuccessfulDeploy({
    owner: "owner", repository: "repo", runId: "3002", workflowPath, environment: "production",
    installationToken: token,
    fetchImpl: fixture({
      runId: "3002",
      runHeadSha: wif2Head,
      runStartedAt: "2026-08-13T12:13:00Z",
      releaseMarker: "wif-2",
    }),
  });
  input.manifest.cutover.reviewed_head_sha = approval.head_sha;
  input.manifest.cutover.merge_sha = approval.merge_sha;
  input.manifest.cutover.wif_1_head_sha = wif1.githubRun.head_sha;
  input.manifest.cutover.workflow_blob_sha = approval.workflow_blob_sha;
  input.manifest.cutover.workflow_sha256 = approval.workflow_sha256;
  input.manifest.post_disable.head_sha = wif2.githubRun.head_sha;
  evidenceByKind(input, "GITHUB_PULL_REQUEST", "cutover-pr").data = approval;
  evidenceByKind(input, "GITHUB_RUN", "wif-1").data = wif1.githubRun;
  evidenceByKind(input, "GITHUB_ENVIRONMENT_REVIEW", "wif-1-review").data = wif1.environmentReview;
  evidenceByKind(input, "GITHUB_RUN", "wif-2").data = wif2.githubRun;
  evidenceByKind(input, "GITHUB_ENVIRONMENT_REVIEW", "wif-2-review").data = wif2.environmentReview;
  for (const name of ["H3-run", "H5-run", "H6-run", "H7-run", "H8-run"]) {
    const run = evidenceByKind(input, "GITHUB_RUN", name).data;
    run.workflow_blob_sha = approval.workflow_blob_sha;
    run.workflow_sha256 = approval.workflow_sha256;
  }
  refreshCheckpointReceipt(input);
  refreshFinalCredentialScan(input);
  await assembleK0Bundle(input);
});

test("GitHub checkpoint collector derives protected review, receipt, push, and required check", async () => {
  const collected = await collectGitHubEvidenceCheckpoint({
    owner: "owner",
    repository: "repo",
    pullNumber: 12,
    receiptPath: "docs/evidence/K0_CHECKPOINT_EXAMPLE.json",
    archivePath,
    installationToken: token,
    fetchImpl: checkpointFixture(),
  });
  assert.equal(collected.observedAt, "2026-08-13T12:18:00Z");
  assert.equal(collected.checkpoint.pull.review_commit_sha, collected.checkpoint.pull.head_sha);
  assert.equal(collected.checkpoint.check.name, "test");
  assert.equal(collected.checkpoint.protection.require_last_push_approval, true);
  assert.equal(collected.checkpoint.protection.required_linear_history, true);
  assert.equal(collected.checkpoint.archive.blob_sha, checkpointArchiveBlob);
  assert.equal(await verifyK0PreDisableArchive(collected.archiveBytes), true);
  assert.equal(JSON.stringify(collected).includes(token), false);
  const returnedArchive = Buffer.from(collected.archiveBytes);
  const archiveMetadata = structuredClone(collected.checkpoint.archive);
  collected.archiveBytes[0] ^= 1;
  assert.deepEqual(collected.checkpoint.archive, archiveMetadata);
  assert.equal(await verifyK0PreDisableArchive(returnedArchive), true);

  const input = validK0BundleInput();
  const artifact = evidenceByKind(input, "GITHUB_EVIDENCE_CHECKPOINT");
  artifact.data = collected.checkpoint;
  artifact.observed_at = collected.observedAt;
  refreshFinalCredentialScan(input);
  await assembleK0Bundle(input);
});

test("GitHub checkpoint collector rejects noncanonical evidence paths before fetch", async () => {
  const invalidPaths = [
    "docs/evidence/../bad.json",
    "docs/evidence/./bad.json",
    "docs/evidence//bad.json",
    "docs/evidence/bad.json/",
    "/docs/evidence/bad.json",
    "docs\\evidence\\bad.json",
    "docs/evidence/%2e%2e/bad.json",
    "docs/evidence/bad.json?raw=1",
    "docs/evidence/bad.json#fragment",
    "docs/evidence/bad\n.json",
    "docs/ｅvidence/bad.json",
    `docs/evidence/${"a".repeat(247)}.json`,
  ];
  for (const field of ["receiptPath", "archivePath"]) {
    for (const value of invalidPaths) {
      let fetches = 0;
      await assert.rejects(() => collectGitHubEvidenceCheckpoint({
        owner: "owner",
        repository: "repo",
        pullNumber: 12,
        receiptPath: "docs/evidence/K0_CHECKPOINT_EXAMPLE.json",
        archivePath,
        [field]: value,
        installationToken: token,
        fetchImpl: async () => { fetches += 1; throw new Error("must not fetch"); },
      }), /path is invalid/);
      assert.equal(fetches, 0);
    }
  }
});

test("GitHub checkpoint collector fails closed on ambiguous or inconsistent API state", async () => {
  const attacks = [
    ["review", (kind, value) => { if (kind === "reviews") value[0].user.id = 20; }],
    ["head", (kind, value) => { if (kind === "reviews") value[0].commit_id = "d".repeat(40); }],
    ["merge", (kind, value) => { if (kind === "runs") value.workflow_runs[0].head_sha = "d".repeat(40); }],
    ["blob", (kind, value) => { if (kind === "receipt") value.sha = "d".repeat(40); }],
    ["content", (kind, value) => { if (kind === "receipt") value.content = Buffer.from("{}\n").toString("base64"); }],
    ["reviewed content", (kind, value, url) => {
      if (kind === "receipt" && url.endsWith(`ref=${"b".repeat(40)}`)) value.sha = "d".repeat(40);
    }],
    ["check", (kind, value) => { if (kind === "checks") value.check_runs[0].name = "other"; }],
    ["app", (kind, value) => { if (kind === "checks") value.check_runs[0].app.id = 1; }],
    ["time", (kind, value) => { if (kind === "checks") value.check_runs[0].completed_at = "2026-08-13T12:10:00Z"; }],
    ["hidden run", (kind, value) => { if (kind === "runs") value.total_count = 2; }],
    ["protection", (kind, value) => {
      if (kind === "protection") value.required_pull_request_reviews.require_last_push_approval = false;
    }],
    ["linear history false", (kind, value) => {
      if (kind === "protection") value.required_linear_history.enabled = false;
    }],
    ["linear history missing", (kind, value) => {
      if (kind === "protection") delete value.required_linear_history;
    }],
  ];
  const args = {
    owner: "owner",
    repository: "repo",
    pullNumber: 12,
    receiptPath: "docs/evidence/K0_CHECKPOINT_EXAMPLE.json",
    archivePath,
    installationToken: token,
  };
  for (const [label, mutate] of attacks) {
    await assert.rejects(() => collectGitHubEvidenceCheckpoint({
      ...args,
      fetchImpl: checkpointFixture({ mutate }),
    }), undefined, label);
  }
  await assert.rejects(() => collectGitHubEvidenceCheckpoint({
    ...args,
    fetchImpl: checkpointFixture({ nextPage: true }),
  }), /paginated/);
});

test("GitHub checkpoint collector rejects archive identity, integrity, coverage, and timeline attacks", async () => {
  const scanId = checkpointArchive.archive.credential_scan.source_id;
  const preId = checkpointArchive.archive.evidence.find(({ id }) => id !== scanId).id;
  const attacks = [
    ["wrong blob", (kind, value) => { if (kind === "archive") value.sha = "d".repeat(40); }],
    ["noncanonical base64", (kind, value) => { if (kind === "archive") value.content += "\n"; }],
    ["wrong archive path", (kind, value) => { if (kind === "archive") value.path += ".wrong"; }],
    ["reviewed head drift", (kind, value, url) => {
      if (kind === "archive" && url.endsWith(`ref=${"b".repeat(40)}`)) {
        replaceContent(value, changedArchive((archive) => { archive.nonce = "alternate-public-nonce-0001"; }));
      }
    }],
    ["merge drift", (kind, value, url) => {
      if (kind === "archive" && url.endsWith(`ref=${"c".repeat(40)}`)) {
        replaceContent(value, changedArchive((archive) => { archive.nonce = "alternate-public-nonce-0002"; }));
      }
    }],
    ["one byte archive", (kind, value) => {
      if (kind === "archive") {
        const bytes = Buffer.from(checkpointArchive.archiveBytes);
        bytes[bytes.length - 2] ^= 1;
        replaceContent(value, bytes);
      }
    }],
    ["missing leak scan", (kind, value) => {
      if (kind === "archive") replaceContent(value, changedArchive((archive) => {
        archive.evidence = archive.evidence.filter(({ id }) => id !== scanId);
        archive.artifacts = archive.artifacts.filter(({ id }) => id !== scanId);
      }));
    }],
    ["extra leak scan", (kind, value) => {
      if (kind === "archive") replaceContent(value, changedArchive((archive) => {
        archive.evidence.push({ ...archive.evidence.find(({ id }) => id === scanId), id: "E999" });
        archive.artifacts.push({ ...archive.artifacts.find(({ id }) => id === scanId), id: "E999" });
        archive.evidence.sort((left, right) => left.id.localeCompare(right.id));
        archive.artifacts.sort((left, right) => left.id.localeCompare(right.id));
      }));
    }],
    ["missing pre artifact", (kind, value) => {
      if (kind === "archive") replaceContent(value, changedArchive((archive) => {
        archive.evidence = archive.evidence.filter(({ id }) => id !== preId);
        archive.artifacts = archive.artifacts.filter(({ id }) => id !== preId);
      }));
    }],
    ["extra pre artifact", (kind, value) => {
      if (kind === "archive") replaceContent(value, changedArchive((archive) => {
        archive.evidence.push({ ...archive.evidence.find(({ id }) => id === preId), id: "E998" });
        archive.artifacts.push({ ...archive.artifacts.find(({ id }) => id === preId), id: "E998" });
        archive.evidence.sort((left, right) => left.id.localeCompare(right.id));
        archive.artifacts.sort((left, right) => left.id.localeCompare(right.id));
      }));
    }],
    ["valid archive receipt mismatch", (kind, value) => {
      if (kind === "receipt") replaceContent(value, changedReceipt((receipt) => {
        receipt.evidence[0].data_sha256 = "0".repeat(64);
      }));
    }],
    ["missing receipt record", (kind, value) => {
      if (kind === "receipt") replaceContent(value, changedReceipt((receipt) => { receipt.evidence.pop(); }));
    }],
    ["extra receipt record", (kind, value) => {
      if (kind === "receipt") replaceContent(value, changedReceipt((receipt) => {
        receipt.evidence.push({ ...receipt.evidence.at(-1), id: "E999" });
      }));
    }],
    ["late seal", (kind, value) => {
      if (kind === "reviews") value[0].submitted_at = "2026-08-13T12:08:59Z";
    }],
  ];
  for (const [label, mutate] of attacks) {
    await assert.rejects(
      () => collectCheckpoint(checkpointFixture({ mutate })),
      undefined,
      label,
    );
  }
});

test("GitHub checkpoint transport rejects duplicate, malformed, unauthenticated, and oversized JSON", async () => {
  const base = checkpointFixture();
  const protection = "/branches/main/protection";
  const rawAttacks = [
    new Response('{"required_status_checks":{},"required_status_\\u0063hecks":{}}', {
      status: 200, headers: { date: "Thu, 13 Aug 2026 12:18:00 GMT" },
    }),
    new Response('{"required_status_checks":{"strict":true,"str\\u0069ct":false}}', {
      status: 200, headers: { date: "Thu, 13 Aug 2026 12:18:00 GMT" },
    }),
    new Response(Buffer.from([0xff]), {
      status: 200, headers: { date: "Thu, 13 Aug 2026 12:18:00 GMT" },
    }),
    new Response("{", {
      status: 200, headers: { date: "Thu, 13 Aug 2026 12:18:00 GMT" },
    }),
    new Response("{}", {
      status: 201, headers: { date: "Thu, 13 Aug 2026 12:18:00 GMT" },
    }),
    new Response("{}", { status: 200 }),
    new Response(null, {
      status: 200, headers: { date: "Thu, 13 Aug 2026 12:18:00 GMT" },
    }),
  ];
  for (const response of rawAttacks) {
    await assert.rejects(() => collectCheckpoint(async (url) =>
      url.endsWith(protection) ? response : base(url)));
  }

  const maximum = 5 * 256 * 1024;
  const prefix = Buffer.from('{"padding":"');
  const suffix = Buffer.from('"}');
  const exactBody = Buffer.concat([prefix, Buffer.alloc(maximum - prefix.length - suffix.length, 0x78), suffix]);
  let exactError;
  try {
    await collectCheckpoint(async (url) => url.endsWith(protection)
      ? new Response(exactBody, {
        status: 200, headers: { date: "Thu, 13 Aug 2026 12:18:00 GMT" },
      }) : base(url));
  } catch (error) {
    exactError = error;
  }
  assert.ok(exactError);
  assert.doesNotMatch(exactError.message, /too large/);

  const overflowing = [
    [new Uint8Array(maximum + 1)],
    [new Uint8Array(700_000), new Uint8Array(maximum - 699_999)],
  ];
  for (const chunks of overflowing) {
    let cancelled = 0;
    const body = new ReadableStream({
      start(controller) { for (const chunk of chunks) controller.enqueue(chunk); },
      cancel() { cancelled += 1; },
    });
    const response = new Response(body, {
      status: 200,
      headers: { date: "Thu, 13 Aug 2026 12:18:00 GMT", "content-length": "1" },
    });
    await assert.rejects(
      () => collectCheckpoint(async (url) => url.endsWith(protection) ? response : base(url)),
      /too large/,
    );
    assert.equal(cancelled, 1);
  }
});

test("GitHub checkpoint transport replaces hostile fetch and response exceptions with static errors", async () => {
  const markerError = () => new Error(checkpointBoundaryMarker);
  const rejectedProxy = new Proxy({}, { get() { throw markerError(); } });
  const fetchAttacks = [
    (url, options) => { throw new Error(`${checkpointBoundaryMarker} ${url} ${options.headers.authorization}`); },
    () => Promise.reject(checkpointBoundaryMarker),
    () => Promise.reject({ message: checkpointBoundaryMarker }),
    () => Promise.reject(rejectedProxy),
    () => ({ then(_resolve, reject) { reject(markerError()); } }),
    () => Object.defineProperty({}, "then", { get() { throw markerError(); } }),
  ];
  for (const attack of fetchAttacks) await rejectsCheckpointWithoutDisclosure(attack);

  const reader = { read: async () => ({ done: true, value: undefined }), cancel: async () => {} };
  const validHeaders = checkpointBoundaryHeaders();
  const validBody = { getReader: () => reader };
  const responseAttacks = [
    () => "not a response",
    () => new Proxy({}, { get() { throw markerError(); } }),
    () => ({ get status() { throw markerError(); }, ok: true, headers: validHeaders, body: validBody }),
    () => ({ status: 200, get ok() { throw markerError(); }, headers: validHeaders, body: validBody }),
    () => ({ status: 200, ok: true, get headers() { throw markerError(); }, body: validBody }),
    () => ({ status: 200, ok: true, headers: Object.defineProperty({}, "get", {
      get() { throw markerError(); },
    }), body: validBody }),
    ...["date", "link", "content-length"].map((target) => () => ({
      status: 200,
      ok: true,
      headers: checkpointBoundaryHeaders((name) => {
        if (name === target) throw markerError();
        return name === "date" ? "Thu, 13 Aug 2026 12:18:00 GMT" : null;
      }),
      body: validBody,
    })),
    () => ({ status: 200, ok: true, headers: checkpointBoundaryHeaders((name) =>
      name === "date" ? "Thu, 13 Aug 2026 12:18:00 GMT"
        : name === "content-length" ? { toString() { throw markerError(); } } : null), body: validBody }),
    () => ({ status: 200, ok: true, headers: validHeaders, get body() { throw markerError(); } }),
    () => ({ status: 200, ok: true, headers: validHeaders,
      body: Object.defineProperty({}, "getReader", { get() { throw markerError(); } }) }),
    () => ({ status: 200, ok: true, headers: validHeaders,
      body: { getReader() { throw markerError(); } } }),
    () => ({ status: 200, ok: true, headers: validHeaders, body: { getReader: () => "bad reader" } }),
    () => checkpointBoundaryResponse(Object.defineProperty({}, "read", {
      get() { throw markerError(); },
    })),
    () => checkpointBoundaryResponse(Object.defineProperty({ read() {} }, "cancel", {
      get() { throw markerError(); },
    })),
  ];
  for (const response of responseAttacks) {
    await rejectsCheckpointWithoutDisclosure(checkpointBoundaryFetch(response));
  }
});

test("GitHub checkpoint transport statically contains hostile body and cancellation failures", async () => {
  const markerError = () => new Error(checkpointBoundaryMarker);
  const readerAttacks = [
    { read() { throw markerError(); }, cancel() {} },
    { read() { return Promise.reject(checkpointBoundaryMarker); }, cancel() {} },
    { read() { return { then(_resolve, reject) { reject(markerError()); } }; }, cancel() {} },
    { read() { return new Proxy({}, { get() { throw markerError(); } }); }, cancel() {} },
    { read() { return { done: false, get value() { throw markerError(); } }; }, cancel() {} },
    { read() { return { done: false, value: new Proxy(new Uint8Array([1]), {
      get(target, property, receiver) {
        if (property === "byteLength") throw markerError();
        return Reflect.get(target, property, receiver);
      },
    }) }; }, cancel() {} },
    { read() { return { done: false, value: new Proxy(new Uint8Array([1]), {
      get(target, property, receiver) {
        if (property === "byteLength") return 1;
        if (property === "length") throw markerError();
        return Reflect.get(target, property, receiver);
      },
    }) }; }, cancel() {} },
  ];
  for (const reader of readerAttacks) {
    await rejectsCheckpointWithoutDisclosure(checkpointBoundaryFetch(() =>
      checkpointBoundaryResponse(reader)));
  }

  await rejectsCheckpointWithoutDisclosure(checkpointBoundaryFetch(() => checkpointBoundaryResponse({
    read: async () => ({ done: true, value: undefined }),
    cancel() { throw markerError(); },
  }, { status: 503, ok: false })));
  await rejectsCheckpointWithoutDisclosure(checkpointBoundaryFetch(() => checkpointBoundaryResponse({
    read: async () => ({ done: false, value: new Uint8Array(5 * 256 * 1024 + 1) }),
    cancel: () => Promise.reject(checkpointBoundaryMarker),
  })));
});

test("GitHub checkpoint transport snapshots the authenticated Date before body awaits", async () => {
  const base = checkpointFixture();
  const protectionUrl = "/branches/main/protection";
  const original = await base(`https://api.github.com/repos/owner/repo${protectionUrl}`);
  const bytes = Buffer.from(await original.arrayBuffer());
  let retained;
  const body = new ReadableStream({
    pull(controller) {
      retained.headers.set("date", "invalid");
      controller.enqueue(bytes);
      controller.close();
    },
  }, { highWaterMark: 0 });
  retained = new Response(body, {
    status: 200, headers: { date: "Thu, 13 Aug 2026 12:18:00 GMT" },
  });
  const collected = await collectCheckpoint(async (url) =>
    url.endsWith(protectionUrl) ? retained : base(url));
  assert.equal(collected.observedAt, "2026-08-13T12:18:00Z");
});
