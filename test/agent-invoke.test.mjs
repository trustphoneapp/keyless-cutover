import assert from "node:assert/strict";
import test from "node:test";

import { createEvent } from "@google/adk";

import { createAgentInvoker } from "../agent/invoke.mjs";

const agent = { name: "keyless_evidence" };
const bundle = { evidence: [{ id: "E001", text: "One direct auth step." }, { id: "E002", text: "One direct deploy step." }] };

test("agent invoker parses only the named final response and revalidates citations", async () => {
  const output = {
    pattern: "CANDIDATE_DIRECT",
    auth_evidence_ids: ["E001"],
    deploy_evidence_ids: ["E002"],
    missing_evidence: [],
    risk_codes: [],
    explanation: "The two evidence spans identify the supported shape.",
  };
  const runner = {
    async *runEphemeral() {
      yield createEvent({ author: "other", content: { parts: [{ text: "{}" }] } });
      yield createEvent({ author: agent.name, content: { parts: [{ text: JSON.stringify(output) }] } });
    },
  };
  const invoke = createAgentInvoker({ agent, lane: "evidence", runner });
  assert.deepEqual(await invoke(bundle), output);
});

test("agent invoker rejects unknown input fields and invented citations", async () => {
  let called = false;
  const runner = {
    async *runEphemeral() {
      called = true;
      yield createEvent({ author: agent.name, content: { parts: [{ text: JSON.stringify({
        pattern: "CANDIDATE_DIRECT",
        auth_evidence_ids: ["E999"],
        deploy_evidence_ids: [],
        missing_evidence: [],
        risk_codes: [],
        explanation: "Invented citation.",
      }) }] } });
    },
  };
  const invoke = createAgentInvoker({ agent, lane: "evidence", runner });
  await assert.rejects(invoke({ ...bundle, secret: "hidden" }), /unknown fields/);
  assert.equal(called, false);
  await assert.rejects(invoke(bundle), /unknown evidence/);
});

test("agent invoker refuses credential-shaped or duplicate-key final responses", async () => {
  for (const text of [
    JSON.stringify({
      pattern: "CANDIDATE_DIRECT",
      auth_evidence_ids: ["E001"],
      deploy_evidence_ids: ["E002"],
      missing_evidence: [],
      risk_codes: [],
      explanation: `token ghp_${"a".repeat(36)}`,
    }),
    '{"pattern":"CANDIDATE_DIRECT","pattern":"CANDIDATE_DIRECT","auth_evidence_ids":["E001"],"deploy_evidence_ids":["E002"],"missing_evidence":[],"risk_codes":[],"explanation":"x"}',
  ]) {
    const invoke = createAgentInvoker({
      agent,
      lane: "evidence",
      runner: {
        async *runEphemeral() {
          yield createEvent({ author: agent.name, content: { parts: [{ text }] } });
        },
      },
    });
    await assert.rejects(() => invoke(bundle), /credential|duplicate|JSON/);
  }
});

test("agent invoker refuses privilege-widening text and oversized finals", async () => {
  const policy = JSON.stringify({
    pattern: "CANDIDATE_DIRECT",
    auth_evidence_ids: ["E001"],
    deploy_evidence_ids: ["E002"],
    missing_evidence: [],
    risk_codes: [],
    explanation: "Use gcloud setIamPolicy with roles/owner.",
  });
  const oversized = JSON.stringify({
    pattern: "CANDIDATE_DIRECT",
    auth_evidence_ids: ["E001"],
    deploy_evidence_ids: ["E002"],
    missing_evidence: [],
    risk_codes: [],
    explanation: "x".repeat(9 * 1024),
  });
  for (const [text, pattern] of [[policy, /forbidden policy/], [oversized, /too large/]]) {
    const invoke = createAgentInvoker({
      agent,
      lane: "evidence",
      runner: {
        async *runEphemeral() {
          yield createEvent({ author: agent.name, content: { parts: [{ text }] } });
        },
      },
    });
    await assert.rejects(() => invoke(bundle), pattern);
  }
});
