import { writeFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { isRfc3339 } from "./rfc3339.mjs";

const DOCUMENT_FIELDS = new Set(["version", "model", "repeats", "predictions", "generated_at"]);

export function requireEvalOutputBasename(value) {
  if (typeof value !== "string" || value.length < 6 || value.length > 128
      || value !== basename(value) || !/^[A-Za-z0-9][A-Za-z0-9._-]*\.json$/.test(value)) {
    throw new Error("eval output basename is invalid");
  }
  return value;
}

export function assertEvalDocument(document) {
  if (!document || typeof document !== "object" || Array.isArray(document)
      || Object.getPrototypeOf(document) !== Object.prototype
      || Object.keys(document).length !== DOCUMENT_FIELDS.size
      || Object.keys(document).some((key) => !DOCUMENT_FIELDS.has(key))
      || document.version !== 1 || document.model !== "gemini-3.5-flash" || document.repeats !== 3
      || !Array.isArray(document.predictions) || !isRfc3339(document.generated_at)) {
    throw new Error("eval prediction document is invalid");
  }
  return document;
}

export function buildEvalDocument(predictions, generatedAt = new Date().toISOString()) {
  return assertEvalDocument({
    version: 1,
    model: "gemini-3.5-flash",
    generated_at: generatedAt,
    repeats: 3,
    predictions,
  });
}

async function main(argv) {
  process.env.OTEL_SDK_DISABLED = "true";
  const outputPath = requireEvalOutputBasename(argv[0]);
  const [{ createAgentInvoker }, { evidenceAgent, recoveryAgent }, { runSealedEvaluation }] = await Promise.all([
    import("../agent/invoke.mjs"),
    import("../agent/taskmaster.mjs"),
    import("../eval/run.mjs"),
  ]);
  const predictions = await runSealedEvaluation({
    evidenceInvoker: createAgentInvoker({ agent: evidenceAgent, lane: "evidence" }),
    recoveryInvoker: createAgentInvoker({ agent: recoveryAgent, lane: "recovery" }),
  });
  const document = buildEvalDocument(predictions);
  await writeFile(resolve(outputPath), `${JSON.stringify(document, null, 2)}\n`, { flag: "wx", mode: 0o600 });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`eval runner failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
