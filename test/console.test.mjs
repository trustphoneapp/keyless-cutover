import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createConsoleServer, renderConsoleHtml } from "../console/server.mjs";
import { loadConsoleStatus } from "../console/status.mjs";

const checkpointPath = fileURLToPath(new URL("../docs/evidence/K0_CHECKPOINT_2026-08-13.json", import.meta.url));
const proofV2ReceiptPath = fileURLToPath(new URL("../docs/evidence/PROOFV2_RECEIPT_2026-08-14.json", import.meta.url));
const predisableReceiptPath = fileURLToPath(new URL("../docs/evidence/K0_PREDISABLE_RECEIPT_2026-08-14.json", import.meta.url));
const disableReceiptPath = fileURLToPath(new URL("../docs/evidence/K0_DISABLE_RECEIPT_2026-08-14.json", import.meta.url));

async function serveConsoleStatus(status) {
  const server = createConsoleServer(status);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try {
    const [htmlResponse, apiResponse] = await Promise.all([
      fetch(`http://127.0.0.1:${port}/`),
      fetch(`http://127.0.0.1:${port}/api/status`),
    ]);
    return { html: await htmlResponse.text(), api: await apiResponse.json() };
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

test("ProofV2 receipt is credential-free, checkpoint-bound, and hash-reconstructable", async () => {
  const [receiptBytes, checkpointBytes] = await Promise.all([
    readFile(proofV2ReceiptPath),
    readFile(checkpointPath),
  ]);
  const receiptText = receiptBytes.toString("utf8");
  assert.doesNotMatch(receiptText, /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"private_key"\s*:|gh[pousr]_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35})/);
  const receipt = JSON.parse(receiptText);
  const checkpoint = JSON.parse(checkpointBytes.toString("utf8"));
  assert.equal(receipt.status, "VERIFIED_INDEPENDENT_REVIEW");
  assert.equal(checkpoint.status, "NO_GO_INCOMPLETE");
  assert.equal(receipt.challenge.id, checkpoint.proof_v2.challenge_id);
  assert.equal(receipt.challenge.proof_digest, checkpoint.proof_v2.proof_digest);
  assert.equal(receipt.workflow.run_id, checkpoint.proof_v2.github_run_id);
  assert.equal(receipt.operator_receipt.receipt_sha256, checkpoint.proof_v2.receipt_sha256);
  const reconstructed = createHash("sha256").update(JSON.stringify({
    challenge_id: receipt.challenge.id,
    proof_digest: receipt.challenge.proof_digest,
    key_id: receipt.key.key_id,
    run_id: receipt.workflow.run_id,
  })).digest("hex");
  assert.equal(reconstructed, receipt.operator_receipt.receipt_sha256);
  assert.equal(receipt.operator_receipt.replay_rejected, true);
  assert.equal(receipt.key.disabled, false);
});

test("pre-disable receipt binds WIF-1, all hostile controls, and the unchanged forbidden revision", async () => {
  const [receiptBytes, checkpointBytes] = await Promise.all([
    readFile(predisableReceiptPath),
    readFile(checkpointPath),
  ]);
  const receipt = JSON.parse(receiptBytes.toString("utf8"));
  const checkpoint = JSON.parse(checkpointBytes.toString("utf8"));
  assert.equal(receipt.status, "K0_PREDISABLE_VERIFIED");
  assert.equal(receipt.release_status, "NO_GO_INCOMPLETE");
  assert.equal(receipt.wif_1.revision, checkpoint.gcp.wif_1_revision);
  assert.equal(receipt.wif_1.github_run_id, checkpoint.pre_disable.wif_1_github_run_id);
  assert.equal(receipt.wif_readback.provider_config_sha256, checkpoint.wif_readback.provider_config_hash);
  assert.equal(receipt.wif_readback.impersonation_binding_sha256, checkpoint.wif_readback.impersonation_binding_hash);
  assert.equal(receipt.forbidden_target.revision_before, receipt.forbidden_target.revision_after);
  assert.deepEqual(receipt.hostile_tests.map(({ id }) => id), ["H1", "H2", "H3", "H4", "H5", "H6", "H7", "H8"]);
  assert.equal(receipt.hostile_tests.every(({ outcome, reached_control, log_sha256 }) =>
    outcome === "DENIED" && reached_control === true && /^[a-f0-9]{64}$/.test(log_sha256)), true);
  assert.deepEqual(receipt.hostile_tests.map(({ run_id }) => run_id),
    checkpoint.pre_disable.hostile_tests.map(({ run_id }) => run_id));
  assert.equal(receipt.blockers.length, 4);
});

test("disable receipt binds the exact key, numeric service account, human actor, and checkpoint", async () => {
  const [receiptBytes, checkpointBytes] = await Promise.all([
    readFile(disableReceiptPath),
    readFile(checkpointPath),
  ]);
  const receiptText = receiptBytes.toString("utf8");
  assert.doesNotMatch(receiptText, /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"private_key"\s*:|gh[pousr]_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35})/);
  const receipt = JSON.parse(receiptText);
  const checkpoint = JSON.parse(checkpointBytes.toString("utf8"));
  assert.equal(receipt.status, "KEY_DISABLED_OBSERVED");
  assert.equal(receipt.key_readback.disabled, true);
  assert.equal(receipt.scope.key_id, checkpoint.key_disable.key_id);
  assert.equal(receipt.scope.service_account_unique_id, checkpoint.key_disable.service_account_unique_id);
  assert.equal(receipt.admin_activity.principal_email, checkpoint.key_disable.human_actor);
  assert.equal(receipt.admin_activity.resource_name, checkpoint.key_disable.audit_resource);
  assert.equal(receipt.admin_activity.insert_id, checkpoint.key_disable.audit_insert_id);
  assert.equal(receipt.admin_activity.resource_name,
    `projects/-/serviceAccounts/${receipt.scope.service_account_unique_id}/keys/${receipt.scope.key_id}`);
  assert.equal(receipt.blockers.length, 3);
});

test("console derives an honest no-go view from the credential-free historical checkpoint", async () => {
  const status = await loadConsoleStatus({ checkpointPath });
  assert.equal(status.status, "NO_GO_INCOMPLETE");
  assert.equal(status.release_ready, false);
  assert.equal(status.cutover_verified, false);
  assert.equal(status.gates.length, 10);
  assert.equal(status.blockers.length, 3);
  assert.match(status.checkpoint_sha256, /^[a-f0-9]{64}$/);
  assert.equal(status.gates.find(({ label }) => label === "H2 wrong repository").state, "historical");
  assert.equal(status.gates.find(({ label }) => label === "H1 foreign owner").state, "historical");
  assert.equal(status.gates.find(({ label }) => label === "ProofV2 replay").state, "historical");
  assert.equal(status.gates.find(({ label }) => label === "H3–H8 controls").state, "historical");
  assert.equal(status.gates.find(({ label }) => label === "Human key disable").state, "historical");
  assert.equal(status.gates.find(({ label }) => label === "Canonical pre-disable archive checkpoint").state, "missing");
  assert.equal(status.gates.find(({ label }) => label === "Fresh disposable v3 transaction").state, "missing");
  assert.match(status.headline, /Historical evidence only/);
  assert.match(status.summary, /cannot satisfy v3/);
  assert.equal(status.blockers.some((item) => /Never re-enable the historical key/.test(item)), true);
  assert.equal(status.blockers.some((item) => /unused release marker/.test(item)), true);
  assert.equal(status.blockers.every((item) => !/\bGO\b|release.?ready|K0\s+COMPLETE|v3\s+complete/i.test(item)), true);
  assert.doesNotMatch(JSON.stringify(status), /Publish the protected RC/);
});

test("checkpoint console copy never promotes authorization or release readiness", async () => {
  const status = await loadConsoleStatus({ checkpointPath });
  assert.equal(status.authorization, "INCOMPLETE");
  assert.equal(status.signature_verified ?? false, false);
  assert.equal(status.release_ready, false);
  assert.equal(status.cutover_verified, false);
  assert.match(status.status, /^NO_GO/);
  assert.doesNotMatch(status.headline, /\bGO\b|PASS|COMPLETE/);
  assert.doesNotMatch(status.summary, /release.?ready|authorized live|v3 complete/i);
  for (const gate of status.gates) {
    if (gate.label === "Gemini necessity") {
      assert.equal(gate.state, "passed");
      continue;
    }
    assert.match(gate.state, /^(historical|missing)$/);
  }
});

test("console rejects a self-asserted success checkpoint instead of falling back", async () => {
  const directory = await mkdtemp(join(tmpdir(), "keyless-console-"));
  const path = join(directory, "checkpoint.json");
  await writeFile(path, JSON.stringify({ version: 1, status: "VERIFIED" }), { mode: 0o600 });
  const status = await loadConsoleStatus({ checkpointPath: path });
  assert.equal(status.status, "NO_GO_VERIFICATION_FAILED");
  assert.equal(status.release_ready, false);
  assert.equal(status.cutover_verified, false);
});

test("checkpoint FIFO fails closed without blocking, output, or fallback", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "keyless-console-fifo-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const fifoPath = join(directory, "checkpoint.fifo");
  const created = spawnSync("mkfifo", [fifoPath], { encoding: "utf8" });
  if (created.error?.code === "ENOENT") {
    t.skip("mkfifo is unavailable");
    return;
  }
  assert.equal(created.status, 0, created.stderr);
  const statusModule = new URL("../console/status.mjs", import.meta.url).href;
  const script = `
    import { loadConsoleStatus } from ${JSON.stringify(statusModule)};
    const status = await loadConsoleStatus({ checkpointPath: process.env.KEYLESS_TEST_FIFO });
    if (status.status !== "NO_GO_VERIFICATION_FAILED" || status.release_ready !== false
        || status.cutover_verified !== false || status.metrics.length !== 0) process.exitCode = 2;
  `;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    encoding: "utf8",
    env: { ...process.env, KEYLESS_TEST_FIFO: fifoPath },
    timeout: 2_000,
    killSignal: "SIGKILL",
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "");
});

test("configured invalid K0 manifest fails closed and never uses checkpoint readiness", async () => {
  const directory = await mkdtemp(join(tmpdir(), "keyless-console-manifest-"));
  const path = join(directory, "manifest.json");
  await writeFile(path, JSON.stringify({ version: 2 }), { mode: 0o600 });
  const status = await loadConsoleStatus({ checkpointPath, manifestPath: path });
  assert.equal(status.status, "NO_GO_VERIFICATION_FAILED");
  assert.deepEqual(status.metrics, []);
});

test("console HTML escapes evidence-derived strings and contains no executable client script", () => {
  const status = {
    version: 1,
    status: "NO_GO_INCOMPLETE",
    authorization: "INCOMPLETE",
    release_ready: false,
    cutover_verified: false,
    signature_verified: false,
    eyebrow: "<checkpoint>",
    headline: "No-go",
    summary: "Evidence only",
    recorded_at: null,
    checkpoint_sha256: null,
    metrics: [{ value: "0/1", label: "<unsafe>" }],
    gates: [{ label: "Gate", state: "missing", detail: "<script>alert(1)</script>" }],
    blockers: ["<img src=x onerror=alert(1)>"],
    sources: [],
    limitations: ["Escaped evidence cannot become executable markup."],
  };
  const html = renderConsoleHtml(status);
  assert.ok(!html.includes("<script>"));
  assert.ok(!html.includes("<img src=x"));
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /No-go · evidence incomplete/);
});

test("console HTML refuses promoted or incomplete status objects", () => {
  const base = {
    version: 1,
    status: "NO_GO_INCOMPLETE",
    authorization: "INCOMPLETE",
    release_ready: false,
    cutover_verified: false,
    signature_verified: false,
    eyebrow: "Evidence incomplete",
    headline: "No proof, no green light.",
    summary: "Missing evidence.",
    recorded_at: null,
    checkpoint_sha256: null,
    metrics: [],
    gates: [],
    blockers: ["blocked"],
    sources: [],
    limitations: ["limit"],
  };
  for (const status of [
    { ...base, release_ready: true },
    { ...base, authorization: "AUTHORIZED" },
    { ...base, status: "GO" },
    { ...base, cutover_verified: true },
    { ...base, final: true },
    { ...base, headline: "GO", status: "NO_GO_INCOMPLETE" },
  ]) {
    assert.throws(() => renderConsoleHtml(status), /fail-closed/);
  }
  assert.doesNotMatch(renderConsoleHtml(base), /\bAUTHORIZED\b|release_ready.: ?true/);
});

test("console routes are read-only and return hardened response headers", async () => {
  const status = await loadConsoleStatus({ checkpointPath });
  const server = createConsoleServer(status);
  status.release_ready = true;
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try {
    const page = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(page.status, 200);
    assert.match(page.headers.get("content-security-policy"), /default-src 'none'/);
    assert.match(page.headers.get("strict-transport-security"), /max-age=31536000/);
    assert.equal(page.headers.get("x-frame-options"), "DENY");
    const mutation = await fetch(`http://127.0.0.1:${port}/api/status`, { method: "POST" });
    assert.equal(mutation.status, 404);
    const apiStatus = await (await fetch(`http://127.0.0.1:${port}/api/status`)).json();
    assert.equal(apiStatus.release_ready, false);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("console server rejects fabricated, promoted, or pre-capture mutated statuses", async () => {
  const legitimate = await loadConsoleStatus({ checkpointPath });
  const unbranded = structuredClone(legitimate);
  const authorized = { ...unbranded,
    status: "K0_VERIFIED_RECEIPT_PENDING", authorization: "AUTHORIZED", signature_verified: true };
  const promotionField = { ...unbranded, final: true };
  const fabricatedHeadline = { ...unbranded, headline: "GO" };
  for (const status of [unbranded, authorized, promotionField, fabricatedHeadline]) {
    assert.throws(() => createConsoleServer(status), /fail-closed/);
  }

  legitimate.headline = "GO";
  assert.throws(() => createConsoleServer(legitimate), /fail-closed/);
  const withExtraField = await loadConsoleStatus({ checkpointPath });
  withExtraField.promotion = true;
  assert.throws(() => createConsoleServer(withExtraField), /fail-closed/);
});

test("console serves only its private snapshot through stateful getters and proxies", async () => {
  const headlineStatus = await loadConsoleStatus({ checkpointPath });
  const safeHeadline = headlineStatus.headline;
  let headlineReads = 0;
  Object.defineProperty(headlineStatus, "headline", {
    configurable: true,
    enumerable: true,
    get() {
      headlineReads += 1;
      return headlineReads < 3 ? safeHeadline : "GO_GETTER_INJECTED";
    },
  });
  const headlineServed = await serveConsoleStatus(headlineStatus);
  assert.equal(headlineReads, 1);
  assert.equal(headlineServed.api.headline, safeHeadline);
  assert.doesNotMatch(headlineServed.html, /GO_GETTER_INJECTED/);

  const nestedStatus = await loadConsoleStatus({ checkpointPath });
  const safeDetail = nestedStatus.gates[0].detail;
  let detailReads = 0;
  Object.defineProperty(nestedStatus.gates[0], "detail", {
    configurable: true,
    enumerable: true,
    get() {
      detailReads += 1;
      return detailReads === 1 ? safeDetail : "GO_NESTED_INJECTED";
    },
  });
  const nestedServed = await serveConsoleStatus(nestedStatus);
  assert.equal(detailReads, 1);
  assert.equal(nestedServed.api.gates[0].detail, safeDetail);
  assert.doesNotMatch(nestedServed.html, /GO_NESTED_INJECTED/);

  const proxyStatus = await loadConsoleStatus({ checkpointPath });
  const originalMetrics = proxyStatus.metrics;
  let metricReads = 0;
  proxyStatus.metrics = new Proxy(originalMetrics, {
    get(target, property, receiver) {
      if (property === "0") {
        metricReads += 1;
        return metricReads === 1
          ? Reflect.get(target, property, receiver)
          : { value: "GO_PROXY_INJECTED", label: "injected" };
      }
      return Reflect.get(target, property, receiver);
    },
  });
  const proxyServed = await serveConsoleStatus(proxyStatus);
  assert.equal(metricReads, 1);
  assert.deepEqual(proxyServed.api.metrics, originalMetrics);
  assert.doesNotMatch(proxyServed.html, /GO_PROXY_INJECTED/);
});

test("legitimate unmodified verifier-failure status is accepted by the server", async () => {
  const status = await loadConsoleStatus({ checkpointPath: "missing-checkpoint.json" });
  assert.equal(status.status, "NO_GO_VERIFICATION_FAILED");
  assert.doesNotThrow(() => createConsoleServer(status));
});
