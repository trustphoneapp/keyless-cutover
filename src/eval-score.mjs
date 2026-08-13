import { readFile } from "node:fs/promises";

import { scoreSealedPredictions } from "../eval/score.mjs";

const path = process.argv[2];
if (!path) throw new Error("usage: npm run score:eval -- predictions.json");
const predictions = JSON.parse(await readFile(path, "utf8"));
const result = scoreSealedPredictions(predictions);
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (!result.pass) process.exitCode = 1;
