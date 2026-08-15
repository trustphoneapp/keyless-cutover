import assert from "node:assert/strict";
import test from "node:test";

import { createKeylessAgentServer } from "../agent/server.mjs";

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

test("agent server exposes health and protects bounded model routes", async (context) => {
  const token = "a".repeat(32);
  const server = createKeylessAgentServer({
    evidenceInvoker: async (value) => ({ count: value.evidence.length }),
    recoveryInvoker: async () => ({ category: "test" }),
    apiToken: token,
  });
  context.after(() => server.close());
  const origin = await listen(server);
  const health = await fetch(`${origin}/healthz`);
  assert.deepEqual(await health.json(), { status: "ok", model: "gemini-3.5-flash", tools: 0 });
  assert.equal((await fetch(`${origin}/v1/evidence`, { method: "POST", body: "{}" })).status, 401);
  assert.equal((await fetch(`${origin}/v1/evidence`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}` },
    body: "{}",
  })).status, 401);
  const response = await fetch(`${origin}/v1/evidence`, {
    method: "POST",
    headers: {
      authorization: "Bearer google-cloud-run-identity-token",
      "x-keyless-api-token": token,
    },
    body: JSON.stringify({ evidence: [{ id: "E001", text: "safe" }] }),
  });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { output: { count: 1 } });

  const wrongMethod = await fetch(`${origin}/v1/evidence`, { method: "GET" });
  assert.equal(wrongMethod.status, 405);
  assert.equal(wrongMethod.headers.get("allow"), "POST");
  assert.deepEqual(await wrongMethod.json(), { error: "method_not_allowed" });

  const { request } = await import("node:http");
  const port = new URL(origin).port;
  const mismatch = await new Promise((resolve, reject) => {
    const req = request({
      hostname: "127.0.0.1",
      port,
      path: "/v1/evidence",
      method: "POST",
      headers: {
        authorization: "Bearer google-cloud-run-identity-token",
        "x-keyless-api-token": token,
        "content-type": "application/json",
        "content-length": "1",
      },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.write(JSON.stringify({ evidence: [{ id: "E001", text: "safe" }] }));
    req.end();
  });
  assert.equal(mismatch.status, 400);

  const missingLength = await new Promise((resolve, reject) => {
    const req = request({
      hostname: "127.0.0.1",
      port,
      path: "/v1/evidence",
      method: "POST",
      headers: {
        authorization: "Bearer google-cloud-run-identity-token",
        "x-keyless-api-token": token,
        "content-type": "application/json",
        "transfer-encoding": "chunked",
      },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.write(JSON.stringify({ evidence: [{ id: "E001", text: "safe" }] }));
    req.end();
  });
  assert.equal(missingLength.status, 400);
});

test("agent server rejects credential-shaped and duplicate-key bodies", async (context) => {
  const token = "b".repeat(32);
  const server = createKeylessAgentServer({
    evidenceInvoker: async () => ({ ok: true }),
    recoveryInvoker: async () => ({ ok: true }),
    apiToken: token,
  });
  context.after(() => server.close());
  const origin = await listen(server);
  const headers = {
    authorization: "Bearer google-cloud-run-identity-token",
    "x-keyless-api-token": token,
    "content-type": "application/json",
  };
  for (const body of [
    JSON.stringify({ evidence: [{ id: "E001", text: `ghp_${"a".repeat(36)}` }] }),
    '{"evidence":[],"evidence":[]}',
  ]) {
    const response = await fetch(`${origin}/v1/evidence`, { method: "POST", headers, body });
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: "request_rejected" });
  }
});
