import { createHash } from "node:crypto";

import { assertCredentialFreeBytes, createCredentialScan } from "./credential-scan.mjs";
import { canonicalJson, createEvidenceArtifact, decodeUtf8, verifyEvidenceArtifacts } from "./evidence-artifact.mjs";
import { verifyK0PreDisableEvidenceSemantics } from "./k0-evidence-semantics.mjs";
import { verifyK0PreDisableFragment } from "./k0-manifest.mjs";
import { timestampNanoseconds } from "./rfc3339.mjs";

const DOMAIN = "KEYLESS_K0_PREDISABLE_ARCHIVE_V1";
const MAX_ARCHIVE = 700 * 1024;
const PLAN_FIELDS = new Set(["version", "transaction_id", "nonce", "scope", "fragment", "evidence"]);
const ARCHIVE_FIELDS = new Set([
  "version", "domain", "transaction_id", "nonce", "scope", "sealed_at", "fragment", "evidence", "artifacts",
  "credential_scan", "ledger_sha256", "artifact_bytes_sha256",
]);
const LEDGER_FIELDS = new Set(["id", "kind", "locator", "observed_at", "sha256"]);
const ENCODED_ARTIFACT_FIELDS = new Set(["id", "bytes_base64"]);
const SCAN_REFERENCE_FIELDS = new Set(["source_id"]);
const SCAN_DATA_FIELDS = new Set(["outcome", "scanner", "scope_hash", "artifact_count"]);
const EVIDENCE_ID = /^E[0-9]{3}$/;
const SHA256 = /^[a-f0-9]{64}$/;

function exactObject(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === fields.size
    && Object.keys(value).every((key) => fields.has(key));
}

function ledgerDigest(evidence) {
  return createHash("sha256")
    .update("KEYLESS_K0_PREDISABLE_LEDGER_V1\0")
    .update(Buffer.from(canonicalJson(evidence), "utf8"))
    .digest("hex");
}

function exactLedger(evidence) {
  return Array.isArray(evidence) && evidence.length > 0 && evidence.length <= 100
    && evidence.every((entry) => exactObject(entry, LEDGER_FIELDS)
      && EVIDENCE_ID.test(entry.id) && typeof entry.kind === "string" && entry.kind
      && typeof entry.locator === "string" && entry.locator && !/[\r\n]/.test(entry.locator)
      && timestampNanoseconds(entry.observed_at) !== null && SHA256.test(entry.sha256))
    && new Set(evidence.map(({ id }) => id)).size === evidence.length
    && evidence.every(({ id }, index) => index === 0 || evidence[index - 1].id < id);
}

function validatePlan(plan) {
  if (!exactObject(plan, PLAN_FIELDS) || plan.version !== 1
      || typeof plan.transaction_id !== "string" || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(plan.transaction_id)
      || typeof plan.nonce !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(plan.nonce)
      || canonicalJson(plan.scope) !== canonicalJson(plan.fragment?.scope)
      || !exactLedger(plan.evidence)) {
    throw new Error("pre-disable archive plan is invalid");
  }
  assertCredentialFreeBytes(Buffer.from(canonicalJson(plan)));
  const structural = verifyK0PreDisableFragment(plan.fragment, plan.evidence);
  if (!structural.ok) throw new Error("pre-disable archive fragment is invalid");
  return plan;
}

function snapshotPlan(plan, artifacts) {
  const captured = structuredClone(plan);
  if (!(artifacts instanceof Map)) throw new Error("pre-disable archive artifacts are invalid");
  const capturedArtifacts = new Map();
  for (const [id, bytes] of artifacts) {
    if (!Buffer.isBuffer(bytes)) throw new Error("pre-disable archive artifacts are invalid");
    capturedArtifacts.set(id, Buffer.from(bytes));
  }
  validatePlan(captured);
  const expected = new Set(captured.evidence.map(({ id }) => id));
  if (capturedArtifacts.size !== expected.size || [...capturedArtifacts.keys()].some((id) => !expected.has(id))) {
    throw new Error("pre-disable archive artifacts do not exactly match the ledger");
  }
  return { plan: captured, artifacts: capturedArtifacts };
}

function nextEvidenceId(evidence) {
  const used = new Set(evidence.map(({ id }) => id));
  for (let number = 1; number <= 999; number += 1) {
    const id = `E${String(number).padStart(3, "0")}`;
    if (!used.has(id)) return id;
  }
  throw new Error("pre-disable archive has no available scan evidence ID");
}

function latestObservation(evidence) {
  return evidence.map(({ observed_at: observedAt }) => observedAt)
    .reduce((latest, value) => timestampNanoseconds(value) > timestampNanoseconds(latest) ? value : latest);
}

function artifactBytesDigest(evidence, artifacts) {
  const digest = createHash("sha256").update("KEYLESS_K0_PREDISABLE_ARTIFACT_BYTES_V1\0");
  for (const { id } of evidence) {
    const bytes = artifacts.get(id);
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    digest.update(id).update("\0").update(length).update(bytes);
  }
  return digest.digest("hex");
}

function decodeArtifact(value) {
  if (!exactObject(value, ENCODED_ARTIFACT_FIELDS) || !EVIDENCE_ID.test(value.id)
      || typeof value.bytes_base64 !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value.bytes_base64)) {
    throw new Error("pre-disable archive encoded artifact is invalid");
  }
  const bytes = Buffer.from(value.bytes_base64, "base64");
  if (!bytes.length || bytes.toString("base64") !== value.bytes_base64) {
    throw new Error("pre-disable archive encoded artifact is invalid");
  }
  return bytes;
}

function freezeJson(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeJson));
  if (value && typeof value === "object") {
    return Object.freeze(Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, freezeJson(item)]),
    ));
  }
  return value;
}

export function parseK0PreDisableArchivePlanBytes(planBytes) {
  if (!Buffer.isBuffer(planBytes) || !planBytes.length || planBytes.length > MAX_ARCHIVE) {
    throw new Error("pre-disable archive plan bytes are invalid");
  }
  let plan;
  try {
    plan = JSON.parse(decodeUtf8(planBytes));
  } catch {
    throw new Error("pre-disable archive plan is not JSON");
  }
  if (!planBytes.equals(Buffer.from(canonicalJson(plan), "utf8"))) {
    throw new Error("pre-disable archive plan is not canonical");
  }
  return validatePlan(plan);
}

async function createFromSnapshot({ plan, artifacts }) {
  const valid = await verifyK0PreDisableEvidenceSemantics(
    plan.fragment,
    plan.evidence,
    async (id) => artifacts.get(id),
  );
  if (!valid.ok) throw new Error("pre-disable archive evidence is invalid");
  const sealedAt = latestObservation(plan.evidence);
  const scanId = nextEvidenceId(plan.evidence);
  const scan = createEvidenceArtifact({
    id: scanId,
    kind: "LEAK_SCAN",
    locator: "credential-scan:predisable-archive",
    observed_at: sealedAt,
    data: createCredentialScan(plan.scope, artifacts),
  });
  const allArtifacts = new Map(artifacts).set(scanId, Buffer.from(scan.artifact));
  const evidence = [...plan.evidence, {
    id: scanId,
    kind: "LEAK_SCAN",
    locator: "credential-scan:predisable-archive",
    observed_at: sealedAt,
    sha256: scan.sha256,
  }].toSorted((left, right) => left.id.localeCompare(right.id));
  const archive = {
    version: 1,
    domain: DOMAIN,
    transaction_id: plan.transaction_id,
    nonce: plan.nonce,
    scope: structuredClone(plan.scope),
    sealed_at: sealedAt,
    fragment: structuredClone(plan.fragment),
    evidence,
    artifacts: evidence.map(({ id }) => ({ id, bytes_base64: allArtifacts.get(id).toString("base64") })),
    credential_scan: { source_id: scanId },
    ledger_sha256: ledgerDigest(evidence),
    artifact_bytes_sha256: artifactBytesDigest(evidence, allArtifacts),
  };
  const archiveBytes = Buffer.from(canonicalJson(archive));
  if (archiveBytes.length > MAX_ARCHIVE) throw new Error("pre-disable archive exceeds the size limit");
  assertCredentialFreeBytes(archiveBytes);
  await verifyK0PreDisableArchive(archiveBytes);
  return { archive, archiveBytes };
}

export async function createK0PreDisableArchive(plan, artifacts) {
  const snapshot = snapshotPlan(plan, artifacts);
  return createFromSnapshot(snapshot);
}

export async function verifyK0PreDisableArchive(archiveBytes) {
  if (!Buffer.isBuffer(archiveBytes) || !archiveBytes.length || archiveBytes.length > MAX_ARCHIVE) {
    throw new Error("pre-disable archive bytes are invalid");
  }
  const captured = Buffer.from(archiveBytes);
  assertCredentialFreeBytes(captured);
  let archive;
  try {
    archive = JSON.parse(decodeUtf8(captured));
  } catch {
    throw new Error("pre-disable archive is not JSON");
  }
  if (!captured.equals(Buffer.from(canonicalJson(archive), "utf8")) || !exactObject(archive, ARCHIVE_FIELDS)
      || archive.version !== 1 || archive.domain !== DOMAIN || !exactLedger(archive.evidence)
      || !exactObject(archive.credential_scan, SCAN_REFERENCE_FIELDS)) {
    throw new Error("pre-disable archive is invalid");
  }
  const scanId = archive.credential_scan.source_id;
  const scanEntries = archive.evidence.filter(({ id, kind }) => id === scanId && kind === "LEAK_SCAN");
  if (scanEntries.length !== 1 || scanEntries[0].locator !== "credential-scan:predisable-archive"
      || scanEntries[0].observed_at !== archive.sealed_at || !Array.isArray(archive.artifacts)
      || archive.artifacts.length !== archive.evidence.length
      || archive.artifacts.some(({ id }, index) => id !== archive.evidence[index].id)) {
    throw new Error("pre-disable archive scan or artifact set is invalid");
  }
  const artifacts = new Map(archive.artifacts.map((encoded) => [encoded.id, decodeArtifact(encoded)]));
  if (artifacts.size !== archive.evidence.length) throw new Error("pre-disable archive artifacts are duplicated");
  const integrity = await verifyEvidenceArtifacts({ evidence: archive.evidence }, async (id) => artifacts.get(id));
  if (!integrity.ok) throw new Error("pre-disable archive artifact integrity failed");
  const preEvidence = archive.evidence.filter(({ id }) => id !== scanId);
  const preArtifacts = new Map(preEvidence.map(({ id }) => [id, artifacts.get(id)]));
  validatePlan({
    version: 1,
    transaction_id: archive.transaction_id,
    nonce: archive.nonce,
    scope: archive.scope,
    fragment: archive.fragment,
    evidence: preEvidence,
  });
  const semantic = await verifyK0PreDisableEvidenceSemantics(
    archive.fragment,
    preEvidence,
    async (id) => preArtifacts.get(id),
  );
  if (!semantic.ok) throw new Error("pre-disable archive fragment evidence is invalid");
  const scanArtifact = JSON.parse(decodeUtf8(artifacts.get(scanId)));
  if (!exactObject(scanArtifact.data, SCAN_DATA_FIELDS)
      || canonicalJson(scanArtifact.data) !== canonicalJson(createCredentialScan(archive.scope, preArtifacts))) {
    throw new Error("pre-disable archive credential scan is invalid");
  }
  if (archive.sealed_at !== latestObservation(archive.evidence)
      || archive.ledger_sha256 !== ledgerDigest(archive.evidence)
      || archive.artifact_bytes_sha256 !== artifactBytesDigest(archive.evidence, artifacts)) {
    throw new Error("pre-disable archive digests or seal time are invalid");
  }
  return true;
}

async function expandArchiveSnapshot(captured) {
  await verifyK0PreDisableArchive(captured);
  const archive = JSON.parse(decodeUtf8(captured));
  const archiveScanId = archive.credential_scan.source_id;
  const storedArtifacts = new Map(archive.artifacts.map((encoded) => [encoded.id, decodeArtifact(encoded)]));
  const evidence = freezeJson(structuredClone(archive.evidence));
  const preEvidence = freezeJson(structuredClone(
    archive.evidence.filter(({ id }) => id !== archiveScanId),
  ));
  const artifactIds = Object.freeze(archive.evidence.map(({ id }) => id));
  const readArtifact = Object.freeze((id) => {
    if (typeof id !== "string" || !storedArtifacts.has(id)) {
      throw new Error("pre-disable archive artifact is not present");
    }
    return Buffer.from(storedArtifacts.get(id));
  });
  return Object.freeze({
    metadata: freezeJson({
      version: archive.version,
      domain: archive.domain,
      transaction_id: archive.transaction_id,
      nonce: archive.nonce,
      sealed_at: archive.sealed_at,
      ledger_sha256: archive.ledger_sha256,
      artifact_bytes_sha256: archive.artifact_bytes_sha256,
    }),
    scope: freezeJson(structuredClone(archive.scope)),
    fragment: freezeJson(structuredClone(archive.fragment)),
    evidence,
    preEvidence,
    archiveScanId,
    artifactIds,
    readArtifact,
  });
}

export function expandK0PreDisableArchive(archiveBytes) {
  if (!Buffer.isBuffer(archiveBytes) || !archiveBytes.length || archiveBytes.length > MAX_ARCHIVE) {
    throw new Error("pre-disable archive bytes are invalid");
  }
  return expandArchiveSnapshot(Buffer.from(archiveBytes));
}
