import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";

process.env.OTEL_SDK_DISABLED = "true";

const outputPath = process.argv[2];
if (!outputPath) throw new Error("usage: npm run run:eval -- predictions.json");

const [{ createAgentInvoker }, { evidenceAgent, recoveryAgent }, { runSealedEvaluation }] = await Promise.all([
  import("../agent/invoke.mjs"),
  import("../agent/taskmaster.mjs"),
  import("../eval/run.mjs"),
]);
const predictions = await runSealedEvaluation({
  evidenceInvoker: createAgentInvoker({ agent: evidenceAgent, lane: "evidence" }),
  recoveryInvoker: createAgentInvoker({ agent: recoveryAgent, lane: "recovery" }),
});
await writeFile(resolve(outputPath), `${JSON.stringify({
  version: 1,
  model: "gemini-3.5-flash",
  generated_at: new Date().toISOString(),
  repeats: 3,
  predictions,
}, null, 2)}\n`, { flag: "wx", mode: 0o600 });
