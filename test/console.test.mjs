import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createConsoleServer, renderConsoleHtml } from "../console/server.mjs";
import { loadConsoleStatus } from "../console/status.mjs";

const checkpointPath = fileURLToPath(new URL("../docs/evidence/K0_CHECKPOINT_2026-08-13.json", import.meta.url));
const proofV2ReceiptPath = fileURLToPath(new URL("../docs/evidence/PROOFV2_RECEIPT_2026-08-14.json", import.meta.url));
const predisableReceiptPath = fileURLToPath(new URL("../docs/evidence/K0_PREDISABLE_RECEIPT_2026-08-14.json", import.meta.url));

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

test("console derives an honest no-go view from the credential-free live checkpoint", async () => {
  const status = await loadConsoleStatus({ checkpointPath });
  assert.equal(status.status, "NO_GO_INCOMPLETE");
  assert.equal(status.release_ready, false);
  assert.equal(status.cutover_verified, false);
  assert.equal(status.gates.length, 8);
  assert.equal(status.blockers.length, 4);
  assert.match(status.checkpoint_sha256, /^[a-f0-9]{64}$/);
  assert.equal(status.gates.find(({ label }) => label === "H2 wrong repository").state, "denied");
  assert.equal(status.gates.find(({ label }) => label === "H1 foreign owner").state, "denied");
  assert.equal(status.gates.find(({ label }) => label === "ProofV2 replay").state, "passed");
  assert.equal(status.gates.find(({ label }) => label === "H3–H8 controls").state, "passed");
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
    release_ready: false,
    cutover_verified: false,
    eyebrow: "<checkpoint>",
    headline: "No-go",
    summary: "Evidence only",
    recorded_at: null,
    checkpoint_sha256: null,
    metrics: [{ value: "0/1", label: "<unsafe>" }],
    gates: [{ label: "Gate", state: "missing", detail: "<script>alert(1)</script>" }],
    blockers: ["<img src=x onerror=alert(1)>"],
    sources: [],
  };
  const html = renderConsoleHtml(status);
  assert.ok(!html.includes("<script>"));
  assert.ok(!html.includes("<img src=x"));
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /No-go · evidence incomplete/);
});

test("console routes are read-only and return hardened response headers", async () => {
  const status = await loadConsoleStatus({ checkpointPath });
  const server = createConsoleServer(status);
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
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
