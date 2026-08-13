import assert from "node:assert/strict";
import test from "node:test";

import { runSealedEvaluation } from "../eval/run.mjs";

test("sealed runner executes three isolated attempts per case without persisting raw failures", async () => {
  let calls = 0;
  let time = 0;
  const invoker = async () => {
    calls += 1;
    if (calls === 2) throw new Error("sensitive provider error");
    return { attempt: calls };
  };
  const predictions = await runSealedEvaluation({
    evidenceInvoker: invoker,
    recoveryInvoker: invoker,
    clock: () => { time += 5; return time; },
  });
  assert.equal(predictions.length, 24);
  assert.equal(predictions.every(({ attempts }) => attempts.length === 3), true);
  assert.equal(calls, 72);
  assert.deepEqual(predictions[0].attempts[1], { repeat: 2, latency_ms: 5, error: "INVOCATION_REJECTED" });
  assert.equal(JSON.stringify(predictions).includes("sensitive provider error"), false);
});
