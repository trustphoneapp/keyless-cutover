import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { canonicalJson, createEvidenceArtifact, verifyEvidenceArtifacts } from "../src/evidence-artifact.mjs";

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
  for (const invalid of [Buffer.from([0xff]), Buffer.from([0xc0, 0xaf]), Buffer.from([0xed, 0xa0, 0x80])]) {
    const result = await verifyEvidenceArtifacts(manifest, async () => invalid);
    assert.equal(result.ok, false);
    assert.match(result.errors.join("\n"), /valid UTF-8/);
  }
  const extra = canonicalJson({ ...JSON.parse(created.artifact), untrusted: true });
  const extraManifest = structuredClone(manifest);
  extraManifest.evidence[0].sha256 = createHash("sha256").update(extra).digest("hex");
  assert.equal((await verifyEvidenceArtifacts(extraManifest, async () => extra)).ok, false);
  assert.throws(() => createEvidenceArtifact({
    ...envelope,
    data: { value: "-----BEGIN PRIVATE KEY-----" },
  }), /credential/);
  assert.doesNotThrow(() => createEvidenceArtifact({ ...envelope, observed_at: "2026-08-13T12:00:00.123456789Z" }));
  assert.throws(() => createEvidenceArtifact({ ...envelope, observed_at: "2026-02-29T12:00:00Z" }), /observed_at/);
});

test("canonical JSON rejects lone UTF-16 surrogates in keys and nested values", async () => {
  for (const value of [
    { value: "\ud800" },
    { value: "\udfff" },
    { nested: ["valid", { value: "\ud800" }] },
    { ["\ud800"]: "value" },
  ]) {
    assert.throws(() => canonicalJson(value), /Unicode surrogate/);
  }
  assert.equal(canonicalJson({ emoji: "😀", nested: ["𝄞"] }), "{\"emoji\":\"😀\",\"nested\":[\"𝄞\"]}\n");
  assert.doesNotThrow(() => createEvidenceArtifact({ ...envelope, data: { value: "valid 😀" } }));
  assert.throws(() => createEvidenceArtifact({ ...envelope, data: { value: "\ud800" } }), /Unicode surrogate/);

  const created = createEvidenceArtifact(envelope);
  const unsafe = Buffer.from(created.artifact.replace('"success"', '"\\ud800"'));
  const manifest = { evidence: [{
    id: envelope.id,
    kind: envelope.kind,
    locator: envelope.locator,
    observed_at: envelope.observed_at,
    sha256: createHash("sha256").update(unsafe).digest("hex"),
  }] };
  const result = await verifyEvidenceArtifacts(manifest, async () => unsafe);
  assert.equal(result.ok, false);
  assert.match(result.errors.join("\n"), /non-JSON value/);
});
