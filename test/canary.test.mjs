import assert from "node:assert/strict";
import test from "node:test";

import { canaryPayload } from "../demo/service/server.mjs";

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
