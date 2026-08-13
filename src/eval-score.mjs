import { readFile } from "node:fs/promises";

import { scoreSealedPredictions } from "../eval/score.mjs";

const path = process.argv[2];
if (!path) throw new Error("usage: npm run score:eval -- predictions.json");
const document = JSON.parse(await readFile(path, "utf8"));
if (document?.version !== 1 || document?.model !== "gemini-3.5-flash" || document?.repeats !== 3) {
  throw new Error("prediction document metadata is invalid");
}
const result = scoreSealedPredictions(document.predictions);
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (!result.pass) process.exitCode = 1;
