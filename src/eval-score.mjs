import { readFile } from "node:fs/promises";

import { scoreSealedPredictions } from "../eval/score.mjs";
import { looksCredentialShaped } from "./credential-shaped.mjs";
import { rejectDuplicateJsonKeys } from "./observation-time.mjs";
import { isRfc3339 } from "./rfc3339.mjs";

const DOCUMENT_FIELDS = new Set(["version", "model", "repeats", "predictions", "generated_at"]);
const REQUIRED_FIELDS = new Set(["version", "model", "repeats", "predictions"]);

const path = process.argv[2];
if (!path) throw new Error("usage: npm run score:eval -- predictions.json");
const text = await readFile(path, "utf8");
if (looksCredentialShaped(text)) throw new Error("prediction document contains credential-shaped material");
rejectDuplicateJsonKeys(text);
const document = JSON.parse(text);
if (!document || typeof document !== "object" || Array.isArray(document)
    || Object.getPrototypeOf(document) !== Object.prototype
    || Object.keys(document).some((key) => !DOCUMENT_FIELDS.has(key))
    || ![...REQUIRED_FIELDS].every((key) => Object.hasOwn(document, key))
    || document.version !== 1 || document.model !== "gemini-3.5-flash" || document.repeats !== 3
    || !Array.isArray(document.predictions)
    || (document.generated_at !== undefined && !isRfc3339(document.generated_at))) {
  throw new Error("prediction document metadata is invalid");
}
const result = scoreSealedPredictions(document.predictions);
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (!result.pass) process.exitCode = 1;
