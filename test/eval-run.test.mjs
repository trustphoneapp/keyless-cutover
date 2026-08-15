import assert from "node:assert/strict";
import test from "node:test";

import { runSealedEvaluation } from "../eval/run.mjs";
import { scoreSealedPredictions } from "../eval/score.mjs";

test("sealed runner executes three isolated attempts per case without persisting raw failures", async () => {
  let calls = 0;
  const invoker = async () => {
    calls += 1;
    if (calls === 2) throw new Error("sensitive provider error");
    return { attempt: calls };
  };
  const predictions = await runSealedEvaluation({
    evidenceInvoker: invoker,
    recoveryInvoker: invoker,
  });
  assert.equal(predictions.length, 24);
  assert.equal(predictions.every(({ attempts, id }) => (
    typeof id === "string"
      && Object.keys({ id, attempts }).length === 2
      && attempts.length === 3
      && attempts.every((attempt) => Object.keys(attempt).sort().join(",") === "output,repeat")
  )), true);
  assert.equal(calls, 72);
  assert.deepEqual(predictions[0].attempts[1], { repeat: 2, output: { status: "INVOCATION_REJECTED" } });
  assert.equal(JSON.stringify(predictions).includes("sensitive provider error"), false);
  assert.equal(JSON.stringify(predictions).includes("latency_ms"), false);
  const scored = scoreSealedPredictions(predictions);
  assert.equal(scored.pass, false);
});
