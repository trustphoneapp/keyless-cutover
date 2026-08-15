import assert from "node:assert/strict";
import test from "node:test";

import {
  assertEvalDocument,
  buildEvalDocument,
  requireEvalOutputBasename,
} from "../src/run-eval.mjs";

test("eval runner accepts only safe basename outputs", () => {
  assert.equal(requireEvalOutputBasename("predictions.json"), "predictions.json");
  for (const value of [
    "../predictions.json",
    "/tmp/predictions.json",
    "dir/predictions.json",
    "predictions",
    ".json",
    "predictions.json\n",
    "",
  ]) {
    assert.throws(() => requireEvalOutputBasename(value), /basename/);
  }
});

test("sealed eval CLI requires KEYLESS_ALLOW_LIVE before model work", async () => {
  const { spawnSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const cli = fileURLToPath(new URL("../src/run-eval.mjs", import.meta.url));
  const result = spawnSync(process.execPath, [cli, "predictions.json"], {
    encoding: "utf8",
    env: { ...process.env, KEYLESS_ALLOW_LIVE: "" },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /KEYLESS_ALLOW_LIVE=1/);
});

test("eval runner refuses incomplete prediction documents before write", () => {
  const document = buildEvalDocument([{ id: "x" }], "2026-08-15T06:00:00.000Z");
  assert.equal(document.model, "gemini-3.5-flash");
  assert.equal(document.repeats, 3);
  assert.throws(() => assertEvalDocument({
    version: 1,
    model: "gemini-3.5-flash",
    repeats: 3,
    predictions: [],
  }), /document/);
  assert.throws(() => assertEvalDocument({
    version: 2,
    model: "gemini-3.5-flash",
    generated_at: "2026-08-15T06:00:00.000Z",
    repeats: 3,
    predictions: [],
  }), /document/);
  assert.throws(() => buildEvalDocument("not-array", "2026-08-15T06:00:00.000Z"), /document/);
  assert.throws(() => buildEvalDocument([], "2026-08-15 06:00:00"), /document/);
});
