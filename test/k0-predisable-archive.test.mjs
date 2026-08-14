import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { canonicalJson } from "../src/evidence-artifact.mjs";
import {
  createK0PreDisableArchive,
  expandK0PreDisableArchive,
  parseK0PreDisableArchivePlanBytes,
  verifyK0PreDisableArchive,
} from "../src/k0-predisable-archive.mjs";
import { validPreDisableArchiveInput } from "./support/k0-predisable.mjs";

function encoded(value) {
  return Buffer.from(canonicalJson(value));
}

function artifactDigest(evidence, artifacts) {
  const digest = createHash("sha256").update("KEYLESS_K0_PREDISABLE_ARTIFACT_BYTES_V1\0");
  for (const { id } of evidence) {
    const bytes = artifacts.get(id);
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    digest.update(id).update("\0").update(length).update(bytes);
  }
  return digest.digest("hex");
}

function ledgerDigest(evidence) {
  return createHash("sha256")
    .update("KEYLESS_K0_PREDISABLE_LEDGER_V1\0")
    .update(canonicalJson(evidence))
    .digest("hex");
}

async function rejectsArchive(archive, mutate) {
  const changed = structuredClone(archive);
  mutate(changed);
  await assert.rejects(() => verifyK0PreDisableArchive(encoded(changed)));
}

test("pre-disable archive is canonical, deterministic, complete, and independently verifiable", async () => {
  const { plan, artifacts } = await validPreDisableArchiveInput();
  const first = await createK0PreDisableArchive(plan, artifacts);
  const second = await createK0PreDisableArchive(
    structuredClone(plan),
    new Map([...artifacts].reverse()),
  );
  assert.deepEqual(first.archiveBytes, second.archiveBytes);
  assert.equal(first.archiveBytes.toString("utf8"), canonicalJson(first.archive));
  assert.equal(first.archive.version, 1);
  assert.equal(first.archive.domain, "KEYLESS_K0_PREDISABLE_ARCHIVE_V1");
  assert.equal(first.archive.evidence.length, plan.evidence.length + 1);
  assert.deepEqual(first.archive.evidence.map(({ id }) => id), first.archive.evidence.map(({ id }) => id).toSorted());
  assert.equal(first.archive.sealed_at, "2026-08-13T12:09:00Z");
  assert.equal(first.archive.credential_scan.source_id,
    first.archive.evidence.find(({ kind }) => kind === "LEAK_SCAN").id);
  assert.equal(first.archive.ledger_sha256, ledgerDigest(first.archive.evidence));
  assert.equal(await verifyK0PreDisableArchive(first.archiveBytes), true);
  assert.equal(JSON.stringify(first.archive).includes("release_ready"), false);
  assert.equal(JSON.stringify(first.archive).includes("signature"), false);
});

test("plan bytes are exact, canonical, credential-free, and contain only pre-disable fields", async () => {
  const { plan, artifacts } = await validPreDisableArchiveInput();
  assert.deepEqual(parseK0PreDisableArchivePlanBytes(encoded(plan)), plan);
  assert.throws(() => parseK0PreDisableArchivePlanBytes(Buffer.concat([Buffer.from(" "), encoded(plan)])), /canonical/);
  assert.throws(() => parseK0PreDisableArchivePlanBytes(Buffer.from([0xff])), /not JSON/);
  assert.throws(() => parseK0PreDisableArchivePlanBytes(Buffer.from(
    encoded(plan).toString("utf8").replace('"example-public-nonce-0001"', '"\\ud800"'),
  )), /Unicode surrogate/);
  assert.throws(() => parseK0PreDisableArchivePlanBytes(encoded({ ...plan, disable: {} })), /plan is invalid/);
  for (const field of ["checkpoint", "disable", "post_disable", "receipt", "signature", "final"]) {
    const changed = structuredClone(plan);
    changed.fragment[field] = {};
    assert.throws(() => parseK0PreDisableArchivePlanBytes(encoded(changed)));
  }
  const credential = `gh${"p"}_${"z".repeat(24)}`;
  const changed = structuredClone(plan);
  changed.evidence[0].locator = credential;
  assert.throws(
    () => parseK0PreDisableArchivePlanBytes(encoded(changed)),
    (error) => error.message === "credential-shaped material detected" && !error.message.includes(credential),
  );
  const encodedCredential = Buffer.from(credential).toString("base64");
  const encodedKeyPlan = structuredClone(plan);
  encodedKeyPlan.scope[encodedCredential] = "clean";
  encodedKeyPlan.fragment.scope[encodedCredential] = "clean";
  await assert.rejects(
    () => createK0PreDisableArchive(encodedKeyPlan, artifacts),
    (error) => error.message === "credential-shaped material detected"
      && !error.message.includes(credential) && !error.message.includes(encodedCredential),
  );
  assert.throws(() => parseK0PreDisableArchivePlanBytes(Buffer.alloc(700 * 1024 + 1)), /bytes are invalid/);
});

test("archive creation snapshots caller-owned plan and artifact bytes once", async () => {
  const { plan, artifacts } = await validPreDisableArchiveInput();
  const originalId = plan.evidence[0].id;
  const originalBytes = Buffer.from(artifacts.get(originalId));
  const pending = createK0PreDisableArchive(plan, artifacts);
  plan.transaction_id = "mutated-after-call";
  plan.fragment.scope.project_id = "mutated-project";
  artifacts.get(originalId).fill(0x78);
  artifacts.set("E999", Buffer.from("later"));
  const result = await pending;
  assert.equal(result.archive.transaction_id, "example-transaction-1");
  assert.equal(result.archive.scope.project_id, "example-project");
  assert.equal(Buffer.from(
    result.archive.artifacts.find(({ id }) => id === originalId).bytes_base64,
    "base64",
  ).equals(originalBytes), true);
  assert.equal(await verifyK0PreDisableArchive(result.archiveBytes), true);
});

test("archive expansion snapshots bytes and exposes only frozen copies", async () => {
  const { plan, artifacts } = await validPreDisableArchiveInput();
  const created = await createK0PreDisableArchive(plan, artifacts);
  const originalBytes = Buffer.from(created.archiveBytes);
  const originalArchive = structuredClone(created.archive);
  const firstId = originalArchive.evidence[0].id;
  const originalArtifact = Buffer.from(
    originalArchive.artifacts.find(({ id }) => id === firstId).bytes_base64,
    "base64",
  );

  const pending = expandK0PreDisableArchive(created.archiveBytes);
  created.archiveBytes.fill(0x78);
  created.archive.transaction_id = "mutated-after-call";
  created.archive.evidence.pop();
  const expanded = await pending;

  assert.equal(expanded.metadata.transaction_id, originalArchive.transaction_id);
  assert.equal(expanded.metadata.nonce, originalArchive.nonce);
  assert.equal(expanded.metadata.sealed_at, originalArchive.sealed_at);
  assert.equal(expanded.archiveScanId, originalArchive.credential_scan.source_id);
  assert.deepEqual(expanded.artifactIds, originalArchive.evidence.map(({ id }) => id));
  assert.deepEqual(expanded.evidence, originalArchive.evidence);
  assert.deepEqual(
    expanded.preEvidence,
    originalArchive.evidence.filter(({ id }) => id !== expanded.archiveScanId),
  );
  assert.equal(expanded.preEvidence.length + 1, expanded.evidence.length);
  assert.equal(expanded.readArtifact(firstId).equals(originalArtifact), true);
  const returned = expanded.readArtifact(firstId);
  returned.fill(0x79);
  assert.equal(expanded.readArtifact(firstId).equals(originalArtifact), true);
  assert.equal(Object.isFrozen(expanded), true);
  assert.equal(Object.isFrozen(expanded.metadata), true);
  assert.equal(Object.isFrozen(expanded.scope), true);
  assert.equal(Object.isFrozen(expanded.fragment), true);
  assert.equal(Object.isFrozen(expanded.evidence), true);
  assert.equal(Object.isFrozen(expanded.evidence[0]), true);
  assert.equal("artifacts" in expanded, false);
  assert.throws(() => expanded.readArtifact("E999"), /not present/);
  assert.throws(() => { expanded.scope.project_id = "mutated"; }, TypeError);
  assert.equal(await verifyK0PreDisableArchive(originalBytes), true);
});

test("archive expansion rejects invalid bytes and incomplete artifact sets", async () => {
  const { plan, artifacts } = await validPreDisableArchiveInput();
  const { archive, archiveBytes } = await createK0PreDisableArchive(plan, artifacts);
  assert.throws(() => expandK0PreDisableArchive({ archiveBytes }), /bytes are invalid/);
  assert.throws(() => expandK0PreDisableArchive(Buffer.alloc(700 * 1024 + 1)), /bytes are invalid/);
  const oneByte = Buffer.from(archiveBytes);
  oneByte[oneByte.length - 2] ^= 1;
  await assert.rejects(() => expandK0PreDisableArchive(oneByte));
  for (const mutate of [
    (changed) => { changed.artifacts.pop(); },
    (changed) => { changed.artifacts.push(structuredClone(changed.artifacts[0])); },
    (changed) => { changed.artifacts[0].bytes_base64 = changed.artifacts[1].bytes_base64; },
  ]) {
    const changed = structuredClone(archive);
    mutate(changed);
    await assert.rejects(() => expandK0PreDisableArchive(encoded(changed)));
  }
});

test("archive creation rejects missing, extra, substituted, and uncheckpointed pre-disable sources", async () => {
  for (const mode of ["missing", "extra", "substitute", "unreferenced"]) {
    const { plan, artifacts } = await validPreDisableArchiveInput();
    const firstId = plan.evidence[0].id;
    if (mode === "missing") artifacts.delete(firstId);
    if (mode === "extra") artifacts.set("E999", Buffer.from("extra"));
    if (mode === "substitute") artifacts.get(firstId)[10] ^= 1;
    if (mode === "unreferenced") {
      plan.evidence.push({ ...plan.evidence[0], id: "E999" });
      plan.evidence.sort((left, right) => left.id.localeCompare(right.id));
      artifacts.set("E999", Buffer.from(artifacts.get(firstId)));
    }
    await assert.rejects(() => createK0PreDisableArchive(plan, artifacts), mode);
  }
});

test("archive verifier rejects malformed, noncanonical, truncated, oversized, and unknown outer bytes", async () => {
  const { plan, artifacts } = await validPreDisableArchiveInput();
  const { archive, archiveBytes } = await createK0PreDisableArchive(plan, artifacts);
  await assert.rejects(() => verifyK0PreDisableArchive(Buffer.from("{")), /not JSON/);
  await assert.rejects(() => verifyK0PreDisableArchive(Buffer.from([0xff])), /not JSON/);
  await assert.rejects(() => verifyK0PreDisableArchive(Buffer.from(
    archiveBytes.toString("utf8").replace('"example-transaction-1"', '"\\ud800"'),
  )), /Unicode surrogate/);
  await assert.rejects(() => verifyK0PreDisableArchive(Buffer.concat([Buffer.from(" "), archiveBytes])), /invalid/);
  await assert.rejects(() => verifyK0PreDisableArchive(archiveBytes.subarray(0, archiveBytes.length - 1)));
  await assert.rejects(() => verifyK0PreDisableArchive(Buffer.alloc(700 * 1024 + 1)), /bytes are invalid/);
  await rejectsArchive(archive, (changed) => { changed.unknown = true; });
  await rejectsArchive(archive, (changed) => { changed.domain = "KEYLESS_K0_PREDISABLE_ARCHIVE_V2"; });
});

test("archive verifier rejects missing, extra, duplicate, reordered, and one-byte-substituted artifacts", async () => {
  const { plan, artifacts } = await validPreDisableArchiveInput();
  const { archive } = await createK0PreDisableArchive(plan, artifacts);
  await rejectsArchive(archive, (changed) => { changed.artifacts.pop(); });
  await rejectsArchive(archive, (changed) => { changed.artifacts.push(structuredClone(changed.artifacts[0])); });
  await rejectsArchive(archive, (changed) => { changed.evidence[1].id = changed.evidence[0].id; });
  await rejectsArchive(archive, (changed) => { changed.evidence.reverse(); changed.artifacts.reverse(); });
  await rejectsArchive(archive, (changed) => {
    const bytes = Buffer.from(changed.artifacts[0].bytes_base64, "base64");
    bytes[10] ^= 1;
    changed.artifacts[0].bytes_base64 = bytes.toString("base64");
  });
});

test("archive verifier recomputes the scan body, ledger digest, byte digest, and sealed time", async () => {
  const { plan, artifacts } = await validPreDisableArchiveInput();
  const { archive } = await createK0PreDisableArchive(plan, artifacts);
  await rejectsArchive(archive, (changed) => { changed.ledger_sha256 = "0".repeat(64); });
  await rejectsArchive(archive, (changed) => {
    changed.ledger_sha256 = createHash("sha256").update(canonicalJson(changed.evidence)).digest("hex");
  });
  await rejectsArchive(archive, (changed) => { changed.artifact_bytes_sha256 = "0".repeat(64); });
  await rejectsArchive(archive, (changed) => { changed.sealed_at = "2026-08-13T12:09:00.000000001Z"; });
  await rejectsArchive(archive, (changed) => {
    const scanId = changed.credential_scan.source_id;
    const encodedArtifact = changed.artifacts.find(({ id }) => id === scanId);
    const scanArtifact = JSON.parse(Buffer.from(encodedArtifact.bytes_base64, "base64").toString("utf8"));
    scanArtifact.data.artifact_count += 1;
    const bytes = Buffer.from(canonicalJson(scanArtifact));
    encodedArtifact.bytes_base64 = bytes.toString("base64");
    changed.evidence.find(({ id }) => id === scanId).sha256 = createHash("sha256").update(bytes).digest("hex");
    const byteMap = new Map(changed.artifacts.map(({ id, bytes_base64: value }) => [id, Buffer.from(value, "base64")]));
    changed.ledger_sha256 = ledgerDigest(changed.evidence);
    changed.artifact_bytes_sha256 = artifactDigest(changed.evidence, byteMap);
  });
});

test("archive verifier rejects credential-shaped outer content without echo", async () => {
  const { plan, artifacts } = await validPreDisableArchiveInput();
  const { archive } = await createK0PreDisableArchive(plan, artifacts);
  const credential = `ya${"29"}.${"q".repeat(24)}`;
  const changed = structuredClone(archive);
  changed.nonce = credential;
  await assert.rejects(
    () => verifyK0PreDisableArchive(encoded(changed)),
    (error) => error.message === "credential-shaped material detected" && !error.message.includes(credential),
  );
});
