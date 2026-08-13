import assert from "node:assert/strict";
import test from "node:test";

import {
  evidenceCandidateSchema,
  recoveryHypothesisSchema,
  validateEvidenceCandidate,
  validateRedactedEvidenceBundle,
  validateRecoveryHypothesis,
} from "../agent/contracts.mjs";
import { taskmaster } from "../agent/taskmaster.mjs";

test("ADK Taskmaster has no mutation tools and strict bounded outputs", () => {
  assert.equal(taskmaster.model, "gemini-3.5-flash");
  assert.deepEqual(taskmaster.evidenceAgent.tools, []);
  assert.deepEqual(taskmaster.recoveryAgent.tools, []);

  assert.equal(evidenceCandidateSchema.safeParse({
    pattern: "CANDIDATE_DIRECT",
    auth_evidence_ids: ["E001"],
    deploy_evidence_ids: ["E002"],
    missing_evidence: [],
    risk_codes: [],
    explanation: "The auth and deploy spans are directly cited.",
  }).success, true);
  assert.equal(recoveryHypothesisSchema.safeParse({
    category: "WORKFLOW_REF_MISMATCH",
    evidence_refs: ["E001", "E002"],
    mismatch: {
      field: "workflow_ref",
      expected_evidence_id: "E001",
      observed_evidence_id: "E002",
    },
    next_observation: "READ_PROVIDER",
    explanation: "The provider and workflow evidence disagree.",
  }).success, true);
  assert.equal(evidenceCandidateSchema.safeParse({ pattern: "CANDIDATE_DIRECT", cel: "true" }).success, false);
  assert.throws(() => validateRedactedEvidenceBundle({
    evidence: [{ id: "E001", text: "-----BEGIN PRIVATE KEY-----" }],
  }), /credential/);
});

test("agent citations must resolve to the authoritative evidence bundle", () => {
  const bundle = {
    evidence: [
      { id: "E001", text: "Expected workflow_ref is owner/repo/.github/workflows/deploy.yml@refs/heads/main." },
      { id: "E002", text: "Observed workflow_ref is owner/repo/.github/workflows/other.yml@refs/heads/main." },
    ],
  };
  assert.equal(validateEvidenceCandidate({
    pattern: "CANDIDATE_DIRECT",
    auth_evidence_ids: ["E001"],
    deploy_evidence_ids: ["E002"],
    missing_evidence: [],
    risk_codes: [],
    explanation: "Both relevant spans are cited.",
  }, bundle).pattern, "CANDIDATE_DIRECT");
  assert.throws(() => validateEvidenceCandidate({
    pattern: "CANDIDATE_DIRECT",
    auth_evidence_ids: ["E999"],
    deploy_evidence_ids: [],
    missing_evidence: [],
    risk_codes: [],
    explanation: "The cited span does not exist.",
  }, bundle), /unknown evidence/);
  assert.equal(validateRecoveryHypothesis({
    category: "WORKFLOW_REF_MISMATCH",
    evidence_refs: ["E001", "E002"],
    mismatch: {
      field: "workflow_ref",
      expected_evidence_id: "E001",
      observed_evidence_id: "E002",
    },
    next_observation: "READ_GITHUB_RUN",
    explanation: "Expected and observed workflow references differ.",
  }, bundle).category, "WORKFLOW_REF_MISMATCH");
});
