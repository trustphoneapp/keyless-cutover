import { InMemoryRunner, isFinalResponse, stringifyContent } from "@google/adk";
import { randomUUID } from "node:crypto";

import {
  validateEvidenceCandidate,
  validateRedactedEvidenceBundle,
  validateRecoveryHypothesis,
} from "./contracts.mjs";
import { textLooksLikeCredential } from "../src/credential-scan.mjs";
import { rejectDuplicateJsonKeys } from "../src/observation-time.mjs";

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
    if (textLooksLikeCredential(finalText)) throw new Error("agent response contains credential-shaped material");
    let output;
    try {
      rejectDuplicateJsonKeys(finalText);
      output = JSON.parse(finalText);
    } catch (error) {
      if (error?.message === "duplicate JSON key") throw new Error("agent response contains duplicate JSON keys");
      if (/credential-shaped/.test(error?.message ?? "")) throw error;
      throw new Error("agent response is not JSON");
    }
    if (!output || typeof output !== "object" || Array.isArray(output)
        || Object.getPrototypeOf(output) !== Object.prototype) {
      throw new Error("agent response is not a plain JSON object");
    }
    return validate(output, bundle);
  };
}
