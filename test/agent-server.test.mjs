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
});
