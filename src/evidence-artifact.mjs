import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";
import { rejectDuplicateJsonKeys } from "./observation-time.mjs";
import { isRfc3339 } from "./rfc3339.mjs";
import { CREDENTIAL_SHAPED as CREDENTIAL } from "./credential-shaped.mjs";

const EVIDENCE_ID = /^E[0-9]{3}$/;
const ARTIFACT_FIELDS = new Set(["version", "id", "kind", "locator", "observed_at", "data"]);
const UTF8 = new TextDecoder("utf-8", { fatal: true });

function validUnicode(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function checkedString(value) {
  if (!validUnicode(value)) throw new Error("JSON string contains an invalid Unicode surrogate");
  return value;
}

function normalize(value) {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") return checkedString(value);
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [checkedString(key), normalize(value[key])]));
  }
  throw new Error("evidence contains a non-JSON value");
}

export function canonicalJson(value) {
  return `${JSON.stringify(normalize(value))}\n`;
}

export function decodeUtf8(bytes) {
  return UTF8.decode(bytes);
}

export function createEvidenceArtifact({ id, kind, locator, observed_at: observedAt, data }) {
  if (typeof id !== "string" || !EVIDENCE_ID.test(id)) throw new Error("evidence ID is invalid");
  if (typeof kind !== "string" || !kind) throw new Error("evidence kind is invalid");
  if (typeof locator !== "string" || !locator || /[\r\n]/.test(locator)) throw new Error("evidence locator is invalid");
  if (!isRfc3339(observedAt)) {
    throw new Error("evidence observed_at is invalid");
  }
  const artifact = canonicalJson({ version: 1, id, kind, locator, observed_at: observedAt, data });
  if (Buffer.byteLength(artifact) > 512_000) throw new Error("evidence artifact is too large");
  if (CREDENTIAL.test(artifact)) throw new Error("evidence artifact contains credential-shaped material");
  return {
    artifact,
    sha256: createHash("sha256").update(artifact).digest("hex"),
  };
}

export async function verifyEvidenceArtifacts(manifest, readArtifact) {
  if (typeof readArtifact !== "function") throw new Error("an evidence artifact reader is required");
  const errors = [];
  const entries = Array.isArray(manifest?.evidence) ? manifest.evidence : [];
  let totalBytes = 0;
  for (const entry of entries) {
    let raw;
    try {
      raw = await readArtifact(entry.id);
    } catch {
      errors.push(`${entry.id} artifact cannot be read`);
      continue;
    }
    if (!Buffer.isBuffer(raw)) raw = Buffer.from(raw);
    totalBytes += raw.length;
    if (raw.length > 512_000 || totalBytes > 5_000_000) {
      errors.push(`${entry.id} artifact exceeds the evidence budget`);
      continue;
    }
    let text;
    try {
      text = decodeUtf8(raw);
    } catch {
      errors.push(`${entry.id} artifact is not valid UTF-8`);
      continue;
    }
    if (CREDENTIAL.test(text)) errors.push(`${entry.id} artifact contains credential-shaped material`);
    let parsed;
    try {
      rejectDuplicateJsonKeys(text);
      parsed = JSON.parse(text);
    } catch (error) {
      errors.push(`${entry.id} artifact is not JSON${/duplicate JSON key/.test(error?.message ?? "") ? " (duplicate key)" : ""}`);
      continue;
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)
        || Object.keys(parsed).length !== ARTIFACT_FIELDS.size
        || Object.keys(parsed).some((key) => !ARTIFACT_FIELDS.has(key))) {
      errors.push(`${entry.id} artifact fields are invalid`);
    }
    let canonicalBytes;
    try {
      canonicalBytes = Buffer.from(canonicalJson(parsed), "utf8");
    } catch {
      errors.push(`${entry.id} artifact contains a non-JSON value`);
      continue;
    }
    if (!raw.equals(canonicalBytes)) errors.push(`${entry.id} artifact is not canonical JSON`);
    if (parsed?.version !== 1 || parsed?.id !== entry.id || parsed?.kind !== entry.kind
        || parsed?.locator !== entry.locator || parsed?.observed_at !== entry.observed_at) {
      errors.push(`${entry.id} artifact envelope does not match the manifest`);
    }
    const digest = createHash("sha256").update(raw).digest("hex");
    if (digest !== entry.sha256) errors.push(`${entry.id} artifact digest does not match`);
  }
  return { ok: errors.length === 0, errors };
}
