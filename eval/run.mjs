import { sealedCases } from "./cases.mjs";

const INVOCATION_REJECTED = Object.freeze({ status: "INVOCATION_REJECTED" });

export async function runSealedEvaluation({ evidenceInvoker, recoveryInvoker, repeats = 3 }) {
  if (typeof evidenceInvoker !== "function" || typeof recoveryInvoker !== "function" || repeats !== 3) {
    throw new Error("sealed evaluation requires two invokers and exactly three repeats");
  }
  const predictions = [];
  for (const testCase of sealedCases) {
    const attempts = [];
    for (let repeat = 1; repeat <= repeats; repeat += 1) {
      try {
        const output = await (testCase.lane === "evidence" ? evidenceInvoker : recoveryInvoker)(testCase.bundle);
        attempts.push({ repeat, output });
      } catch {
        attempts.push({ repeat, output: structuredClone(INVOCATION_REJECTED) });
      }
    }
    predictions.push({ id: testCase.id, attempts });
  }
  return predictions;
}
