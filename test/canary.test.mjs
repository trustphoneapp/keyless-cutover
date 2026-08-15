import assert from "node:assert/strict";
import test from "node:test";

import { canaryPayload, handleCanaryRequest } from "../demo/service/server.mjs";

test("canary exposes only the independently observable release identity", () => {
  assert.deepEqual(canaryPayload({ K_SERVICE: "keyless-demo", K_REVISION: "keyless-demo-wif-1", RELEASE: "wif-1" }), {
    service: "keyless-demo",
    revision: "keyless-demo-wif-1",
    release: "wif-1",
  });
  assert.deepEqual(Object.keys(canaryPayload({ K_SERVICE: "a", K_REVISION: "b", RELEASE: "c", SECRET: "nope" })).sort(), [
    "release", "revision", "service",
  ]);
});

test("canary server allows only GET / and GET /healthz", () => {
  const env = { K_SERVICE: "keyless-demo", K_REVISION: "keyless-demo-wif-1", RELEASE: "wif-1" };
  for (const [method, url, status, body] of [
    ["GET", "/", 200, true],
    ["GET", "/healthz", 204, false],
    ["POST", "/", 404, false],
    ["GET", "/evil", 404, false],
    ["GET", "/../x", 404, false],
    ["HEAD", "/healthz", 404, false],
  ]) {
    let code;
    let payload = "";
    handleCanaryRequest({ method, url }, {
      writeHead(nextCode) { code = nextCode; },
      end(value) { if (value !== undefined) payload = String(value); },
    }, env);
    assert.equal(code, status);
    if (body) {
      assert.equal(payload, `${JSON.stringify(canaryPayload(env))}\n`);
    } else {
      assert.equal(payload, "");
    }
  }
});
