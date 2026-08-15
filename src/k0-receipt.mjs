import { createHash } from "node:crypto";

import { canonicalJson, decodeUtf8 } from "./evidence-artifact.mjs";
import { looksCredentialShaped } from "./credential-shaped.mjs";
import { verifyK0Bundle } from "./k0-bundle.mjs";
import { rejectDuplicateJsonKeys } from "./observation-time.mjs";
import { isRfc3339 } from "./rfc3339.mjs";

const RECEIPT_FIELDS = new Set([
  "version", "domain", "receipt_id", "issued_at", "authorization", "status", "release_ready",
  "manifest_sha256", "evidence", "scope", "verified_results", "limitations",
]);
const RESULT_FIELDS = new Set([
  "proof", "cutover", "wif", "hostile_tests", "legacy_baseline", "disable", "legacy_after_disable", "post_disable", "leak_scan",
]);
const EVIDENCE_FIELDS = new Set(["id", "kind", "sha256"]);
const SCOPE_FIELDS = new Set([
  "owner_id", "repository_id", "workflow_path", "proof_workflow_path", "legacy_workflow_path",
  "h1_workflow_path", "h2_workflow_path", "h4_workflow_path",
  "project_id", "project_number", "region",
  "service_account_email", "service_account_unique_id", "key_id", "allowed_service", "forbidden_service",
]);
const SHA256 = /^[a-f0-9]{64}$/;

function exactObject(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === fields.size
    && Object.keys(value).every((key) => fields.has(key));
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function snapshotBundle({ manifestBytes, manifest, artifacts }) {
  if (!Buffer.isBuffer(manifestBytes) || !manifestBytes.length || manifestBytes.length > 1_000_000) {
    throw new Error("K0 manifest bytes are invalid");
  }
  const capturedManifestBytes = Buffer.from(manifestBytes);
  let parsedManifest;
  try {
    const text = decodeUtf8(capturedManifestBytes);
    rejectDuplicateJsonKeys(text);
    parsedManifest = JSON.parse(text);
  } catch (error) {
    if (error?.message === "duplicate JSON key") {
      throw new Error("K0 manifest bytes contain duplicate JSON keys");
    }
    throw new Error("K0 manifest bytes are not JSON");
  }
  let suppliedManifestBytes;
  try {
    suppliedManifestBytes = canonicalJson(manifest);
  } catch {
    throw new Error("K0 manifest object is invalid");
  }
  if (!capturedManifestBytes.equals(Buffer.from(canonicalJson(parsedManifest), "utf8"))
      || !capturedManifestBytes.equals(Buffer.from(suppliedManifestBytes, "utf8"))) {
    throw new Error("K0 manifest object and canonical bytes do not match");
  }
  if (!(artifacts instanceof Map)) throw new Error("K0 artifact bytes are invalid");
  const capturedArtifacts = new Map();
  for (const [id, bytes] of artifacts) {
    if (!Buffer.isBuffer(bytes)) throw new Error("K0 artifact bytes are invalid");
    capturedArtifacts.set(id, Buffer.from(bytes));
  }
  return { manifest: parsedManifest, manifestBytes: capturedManifestBytes, artifacts: capturedArtifacts };
}

function receiptFor(manifest, manifestBytes) {
  const manifestSha256 = sha256(manifestBytes);
  return {
    version: 1,
    domain: "KEYLESS_K0_PENDING_RECEIPT_V1",
    receipt_id: manifestSha256,
    issued_at: manifest.assembled_at,
    authorization: "RECOLLECTION_REQUIRED",
    status: "K0_VERIFIED_RECEIPT_PENDING",
    release_ready: false,
    manifest_sha256: manifestSha256,
    evidence: [...manifest.evidence]
      .sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0)
      .map(({ id, kind, sha256: digest }) => ({ id, kind, sha256: digest })),
    scope: structuredClone(manifest.scope),
    verified_results: structuredClone({
      proof: manifest.proof,
      cutover: manifest.cutover,
      wif: manifest.wif,
      hostile_tests: manifest.hostile_tests,
      legacy_baseline: manifest.legacy_baseline,
      disable: manifest.disable,
      legacy_after_disable: manifest.legacy_after_disable,
      post_disable: manifest.post_disable,
      leak_scan: manifest.leak_scan,
    }),
    limitations: structuredClone(manifest.limitations),
  };
}

export function parseK0ReceiptBytes(receiptBytes) {
  if (!Buffer.isBuffer(receiptBytes) || !receiptBytes.length || receiptBytes.length > 1_000_000) {
    throw new Error("K0 receipt bytes are invalid");
  }
  let receipt;
  try {
    const text = decodeUtf8(receiptBytes);
    if (looksCredentialShaped(text)) throw new Error("K0 receipt contains credential-shaped material");
    rejectDuplicateJsonKeys(text);
    receipt = JSON.parse(text);
  } catch (error) {
    if (error?.message === "K0 receipt contains credential-shaped material") throw error;
    if (error?.message === "duplicate JSON key") throw new Error("K0 receipt contains duplicate JSON keys");
    throw new Error("K0 receipt is not JSON");
  }
  if (!receiptBytes.equals(Buffer.from(canonicalJson(receipt), "utf8"))
      || !exactObject(receipt, RECEIPT_FIELDS)
      || receipt.version !== 1 || receipt.domain !== "KEYLESS_K0_PENDING_RECEIPT_V1"
      || receipt.authorization !== "RECOLLECTION_REQUIRED"
      || receipt.status !== "K0_VERIFIED_RECEIPT_PENDING" || receipt.release_ready !== false
      || !isRfc3339(receipt.issued_at)
      || !SHA256.test(receipt.receipt_id ?? "") || receipt.receipt_id !== receipt.manifest_sha256
      || !Array.isArray(receipt.evidence) || receipt.evidence.length < 1 || receipt.evidence.length > 100
      || receipt.evidence.some((item) => !exactObject(item, EVIDENCE_FIELDS)
        || !/^E\d{3}$/.test(item.id) || typeof item.kind !== "string" || !item.kind || !SHA256.test(item.sha256))
      || new Set(receipt.evidence.map(({ id }) => id)).size !== receipt.evidence.length
      || receipt.evidence.some(({ id }, index) => index > 0 && receipt.evidence[index - 1].id >= id)
      || !exactObject(receipt.scope, SCOPE_FIELDS)
      || !exactObject(receipt.verified_results, RESULT_FIELDS)
      || !Array.isArray(receipt.limitations) || !receipt.limitations.length
      || receipt.limitations.some((value) => typeof value !== "string" || !value || value.length > 2048 || /[\r\n]/.test(value))) {
    throw new Error("K0 receipt is invalid");
  }
  return receipt;
}

async function createFromSnapshot(snapshot) {
  await verifyK0Bundle({ manifest: snapshot.manifest, artifacts: snapshot.artifacts });
  const receipt = receiptFor(snapshot.manifest, snapshot.manifestBytes);
  const receiptBytes = Buffer.from(canonicalJson(receipt));
  return { receipt, receiptBytes };
}

export async function createK0Receipt(bundle) {
  const snapshot = snapshotBundle(bundle);
  return createFromSnapshot(snapshot);
}

export async function verifyK0Receipt({ receiptBytes, ...bundle }) {
  if (!Buffer.isBuffer(receiptBytes)) throw new Error("K0 receipt bytes are invalid");
  const capturedReceiptBytes = Buffer.from(receiptBytes);
  parseK0ReceiptBytes(capturedReceiptBytes);
  const snapshot = snapshotBundle(bundle);
  const expected = await createFromSnapshot(snapshot);
  if (!capturedReceiptBytes.equals(expected.receiptBytes)) throw new Error("K0 receipt does not match the verified bundle");
  return true;
}
