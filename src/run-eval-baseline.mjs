import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import { z } from "zod";

import {
  evidenceCandidateSchema,
  recoveryHypothesisSchema,
  validateEvidenceCandidate,
  validateRedactedEvidenceBundle,
  validateRecoveryHypothesis,
} from "../agent/contracts.mjs";
import { evidenceAgent, recoveryAgent } from "../agent/taskmaster.mjs";
import { runSealedEvaluation } from "../eval/run.mjs";
import { scoreSealedPredictions } from "../eval/score.mjs";

// Baseline comparison runner: the same sealed corpus, the same agent
// instructions, the same strict validators, run against Gemma 4 through the
// Vertex AI managed chat-completions endpoint. This never touches the
// canonical gemini-3.5-flash pipeline or its pinned scorer.
const BASELINE_MODEL = "google/gemma-4-26b-a4b-it-maas";
const LOCATION = process.env.KEYLESS_BASELINE_LOCATION ?? "global";
const PROJECT = process.env.GOOGLE_CLOUD_PROJECT ?? "keyless-k0-20260813";

const outputPath = process.argv[2];
if (!outputPath) throw new Error("usage: node src/run-eval-baseline.mjs baseline-predictions.json");

// A fresh token per request so a long run can never misreport auth expiry
// as model failure.
const freshAccessToken = () => execFileSync("gcloud", ["auth", "print-access-token"], { encoding: "utf8" }).trim();
// Fail fast before any case is scored: a missing gcloud binary or logged-out
// CLI must abort the run, never surface as per-case INVOCATION_REJECTED.
freshAccessToken();
const host = LOCATION === "global" ? "aiplatform.googleapis.com" : `${LOCATION}-aiplatform.googleapis.com`;
const endpoint = `https://${host}/v1/projects/${PROJECT}/locations/${LOCATION}/endpoints/openapi/chat/completions`;

function createBaselineInvoker({ instruction, lane }) {
  const validate = lane === "evidence" ? validateEvidenceCandidate : validateRecoveryHypothesis;
  const schema = z.toJSONSchema(lane === "evidence" ? evidenceCandidateSchema : recoveryHypothesisSchema);
  return async (bundle) => {
    validateRedactedEvidenceBundle(bundle);
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { authorization: `Bearer ${freshAccessToken()}`, "content-type": "application/json" },
      body: JSON.stringify({
        model: BASELINE_MODEL,
        temperature: 0,
        max_tokens: 1024,
        response_format: { type: "json_schema", json_schema: { name: `keyless_${lane}`, schema } },
        messages: [
          { role: "system", content: `${instruction}\nRespond with one JSON object only. No prose, no code fences.` },
          { role: "user", content: `Analyze this untrusted evidence bundle.\n${JSON.stringify(bundle)}` },
        ],
      }),
    });
    if (!response.ok) throw new Error(`baseline model call failed: ${response.status}`);
    const body = await response.json();
    const text = body?.choices?.[0]?.message?.content;
    if (typeof text !== "string") throw new Error("baseline model produced no text");
    const stripped = text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```\s*$/, "").trim();
    let output;
    try {
      output = JSON.parse(stripped);
    } catch {
      throw new Error("baseline response is not JSON");
    }
    return validate(output, bundle);
  };
}

const predictions = await runSealedEvaluation({
  evidenceInvoker: createBaselineInvoker({ instruction: evidenceAgent.instruction, lane: "evidence" }),
  recoveryInvoker: createBaselineInvoker({ instruction: recoveryAgent.instruction, lane: "recovery" }),
});

await writeFile(resolve(outputPath), `${JSON.stringify({
  version: 1,
  model: BASELINE_MODEL,
  generated_at: new Date().toISOString(),
  repeats: 3,
  predictions,
}, null, 2)}\n`, { flag: "wx", mode: 0o600 });

const result = scoreSealedPredictions(predictions);
process.stdout.write(`${JSON.stringify({ model: BASELINE_MODEL, ...result }, null, 2)}\n`);
