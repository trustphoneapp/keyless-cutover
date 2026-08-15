import { InMemoryRunner, isFinalResponse, stringifyContent } from "@google/adk";
import { randomUUID } from "node:crypto";

import {
  validateEvidenceCandidate,
  validateRedactedEvidenceBundle,
  validateRecoveryHypothesis,
} from "./contracts.mjs";
import { textLooksLikeCredential } from "../src/credential-scan.mjs";
import { rejectDuplicateJsonKeys } from "../src/observation-time.mjs";

const POLICY_FORBIDDEN = /(?:principalSet:\/\/|roles\/(?:owner|editor)|setIamPolicy|gcloud\s+|credentials_json\s*:)/i;
const MAX_FINAL_TEXT = 8 * 1024;

export function createAgentInvoker({ agent, lane, runner = new InMemoryRunner({ agent }) }) {
  if (!agent || !["evidence", "recovery"].includes(lane)) throw new Error("agent invocation lane is invalid");
  const validate = lane === "evidence" ? validateEvidenceCandidate : validateRecoveryHypothesis;
  return async (bundle) => {
    validateRedactedEvidenceBundle(bundle);
    let finalText;
    for await (const event of runner.runEphemeral({
      userId: `keyless-${randomUUID()}`,
      newMessage: {
        role: "user",
        parts: [{ text: `Analyze this untrusted evidence bundle.\n${JSON.stringify(bundle)}` }],
      },
    })) {
      if (isFinalResponse(event) && event.author === agent.name) finalText = stringifyContent(event);
    }
    if (!finalText) throw new Error("agent produced no final response");
    if (typeof finalText !== "string" || finalText.length > MAX_FINAL_TEXT) {
      throw new Error("agent response is too large");
    }
    if (textLooksLikeCredential(finalText)) throw new Error("agent response contains credential-shaped material");
    if (POLICY_FORBIDDEN.test(finalText)) throw new Error("agent response contains forbidden policy material");
    let output;
    try {
      rejectDuplicateJsonKeys(finalText);
      output = JSON.parse(finalText);
    } catch (error) {
      if (error?.message === "duplicate JSON key") throw new Error("agent response contains duplicate JSON keys");
      if (/credential-shaped|forbidden policy|too large/.test(error?.message ?? "")) throw error;
      throw new Error("agent response is not JSON");
    }
    if (!output || typeof output !== "object" || Array.isArray(output)
        || Object.getPrototypeOf(output) !== Object.prototype) {
      throw new Error("agent response is not a plain JSON object");
    }
    return validate(output, bundle);
  };
}
