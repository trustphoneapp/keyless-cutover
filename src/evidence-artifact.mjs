import { createHash } from "node:crypto";

const CREDENTIAL = /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"private_key"\s*:|ya29\.[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35})/;
const EVIDENCE_ID = /^E[0-9]{3}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

function normalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, normalize(value[key])]));
  }
  throw new Error("evidence contains a non-JSON value");
}

export function canonicalJson(value) {
  return `${JSON.stringify(normalize(value))}\n`;
}

export function createEvidenceArtifact({ id, kind, locator, observed_at: observedAt, data }) {
  if (typeof id !== "string" || !EVIDENCE_ID.test(id)) throw new Error("evidence ID is invalid");
  if (typeof kind !== "string" || !kind) throw new Error("evidence kind is invalid");
  if (typeof locator !== "string" || !locator || /[\r\n]/.test(locator)) throw new Error("evidence locator is invalid");
  if (typeof observedAt !== "string" || !TIMESTAMP.test(observedAt) || !Number.isFinite(Date.parse(observedAt))) {
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
    const text = raw.toString("utf8");
    if (CREDENTIAL.test(text)) errors.push(`${entry.id} artifact contains credential-shaped material`);
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      errors.push(`${entry.id} artifact is not JSON`);
      continue;
    }
    let canonical;
    try {
      canonical = canonicalJson(parsed);
    } catch {
      errors.push(`${entry.id} artifact contains a non-JSON value`);
      continue;
    }
    if (text !== canonical) errors.push(`${entry.id} artifact is not canonical JSON`);
    if (parsed?.version !== 1 || parsed?.id !== entry.id || parsed?.kind !== entry.kind
        || parsed?.locator !== entry.locator || parsed?.observed_at !== entry.observed_at) {
      errors.push(`${entry.id} artifact envelope does not match the manifest`);
    }
    const digest = createHash("sha256").update(raw).digest("hex");
    if (digest !== entry.sha256) errors.push(`${entry.id} artifact digest does not match`);
  }
  return { ok: errors.length === 0, errors };
}
