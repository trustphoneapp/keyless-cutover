import assert from "node:assert/strict";
import test from "node:test";

import { createEvidenceArtifact, verifyEvidenceArtifacts } from "../src/evidence-artifact.mjs";

const envelope = {
  id: "E001",
  kind: "GITHUB_RUN",
  locator: "github-run:123",
  observed_at: "2026-08-13T12:00:00Z",
  data: { conclusion: "success", run_id: "123" },
};

test("evidence artifacts are canonical, bounded, credential-free, and digest-bound", async () => {
  const created = createEvidenceArtifact(envelope);
  const manifest = { evidence: [{ ...envelope, data: undefined, sha256: created.sha256 }] };
  delete manifest.evidence[0].data;
  assert.equal((await verifyEvidenceArtifacts(manifest, async () => created.artifact)).ok, true);

  const changed = created.artifact.replace("success", "failure");
  assert.equal((await verifyEvidenceArtifacts(manifest, async () => changed)).ok, false);
  assert.equal((await verifyEvidenceArtifacts(manifest, async () => ` ${created.artifact}`)).ok, false);
  assert.throws(() => createEvidenceArtifact({
    ...envelope,
    data: { value: "-----BEGIN PRIVATE KEY-----" },
  }), /credential/);
});
