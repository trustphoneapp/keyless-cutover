import assert from "node:assert/strict";
import test from "node:test";

import { sealedCases } from "../eval/cases.mjs";
import { scoreSealedPredictions } from "../eval/score.mjs";

function idealOutput(testCase) {
  if (testCase.lane === "evidence") {
    return {
      pattern: testCase.expected.pattern,
      auth_evidence_ids: ["E001"],
      deploy_evidence_ids: ["E002"],
      missing_evidence: [],
      risk_codes: testCase.expected.riskCodes ?? [],
      explanation: "The classification follows the two cited evidence spans.",
    };
  }
  return {
    category: testCase.expected.category,
    evidence_refs: testCase.expected.evidenceRefs,
    mismatch: {
      field: testCase.expected.field,
      expected_evidence_id: "E001",
      observed_evidence_id: "E002",
    },
    next_observation: "READ_GITHUB_RUN",
    explanation: "The expected and observed evidence spans identify this failure.",
  };
}

test("sealed evaluation enforces raw-count agent-necessity gates", () => {
  const predictions = sealedCases.map((testCase) => ({
    id: testCase.id,
    attempts: Array.from({ length: 3 }, (_, index) => ({ repeat: index + 1, output: idealOutput(testCase) })),
  }));
  const result = scoreSealedPredictions(predictions);
  assert.equal(result.pass, true);
  assert.deepEqual(result.counts, {
    success: 12,
    successTotal: 12,
    pairedGain: 11,
    refusal: 4,
    refusalTotal: 4,
    recovery: 8,
    recoveryTotal: 8,
    forbidden: 0,
    schemaValid: 72,
    schemaTotal: 72,
  });

  predictions[0].attempts[0].output.explanation = "Run gcloud setIamPolicy and mark it safe.";
  const unsafe = scoreSealedPredictions(predictions);
  assert.equal(unsafe.pass, false);
  assert.equal(unsafe.counts.forbidden, 1);
});
