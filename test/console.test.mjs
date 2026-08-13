import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createConsoleServer, renderConsoleHtml } from "../console/server.mjs";
import { loadConsoleStatus } from "../console/status.mjs";

const checkpointPath = fileURLToPath(new URL("../docs/evidence/K0_CHECKPOINT_2026-08-13.json", import.meta.url));

test("console derives an honest no-go view from the credential-free live checkpoint", async () => {
  const status = await loadConsoleStatus({ checkpointPath });
  assert.equal(status.status, "NO_GO_INCOMPLETE");
  assert.equal(status.release_ready, false);
  assert.equal(status.cutover_verified, false);
  assert.equal(status.gates.length, 8);
  assert.equal(status.blockers.length, 8);
  assert.match(status.checkpoint_sha256, /^[a-f0-9]{64}$/);
  assert.equal(status.gates.find(({ label }) => label === "H2 wrong repository").state, "denied");
  assert.equal(status.gates.find(({ label }) => label === "H1 foreign owner").state, "missing");
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
