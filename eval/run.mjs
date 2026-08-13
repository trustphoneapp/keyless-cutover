import { sealedCases } from "./cases.mjs";

export async function runSealedEvaluation({ evidenceInvoker, recoveryInvoker, repeats = 3, clock = () => Date.now() }) {
  if (typeof evidenceInvoker !== "function" || typeof recoveryInvoker !== "function" || repeats !== 3) {
    throw new Error("sealed evaluation requires two invokers and exactly three repeats");
  }
  const predictions = [];
  for (const testCase of sealedCases) {
    const attempts = [];
    for (let repeat = 1; repeat <= repeats; repeat += 1) {
      const started = clock();
      try {
        const output = await (testCase.lane === "evidence" ? evidenceInvoker : recoveryInvoker)(testCase.bundle);
        attempts.push({ repeat, latency_ms: Math.max(0, clock() - started), output });
      } catch {
        attempts.push({ repeat, latency_ms: Math.max(0, clock() - started), error: "INVOCATION_REJECTED" });
      }
    }
    predictions.push({ id: testCase.id, lane: testCase.lane, attempts });
  }
  return predictions;
}
