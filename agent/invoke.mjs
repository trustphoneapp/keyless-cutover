import { InMemoryRunner, isFinalResponse, stringifyContent } from "@google/adk";
import { randomUUID } from "node:crypto";

import {
  validateEvidenceCandidate,
  validateRedactedEvidenceBundle,
  validateRecoveryHypothesis,
} from "./contracts.mjs";

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
    let output;
    try {
      output = JSON.parse(finalText);
    } catch {
      throw new Error("agent response is not JSON");
    }
    return validate(output, bundle);
  };
}
