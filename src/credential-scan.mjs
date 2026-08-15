import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";

import { canonicalJson } from "./evidence-artifact.mjs";
import { rejectDuplicateJsonKeys } from "./observation-time.mjs";

const MAX_INPUT = 700 * 1024;
const MAX_SINGLE_DECODED = 512 * 1024;
const MAX_TOTAL_DECODED = 2 * 1024 * 1024;
const MAX_CANDIDATES = 2_048;
const MAX_DEPTH = 4;
const MAX_JSON_DEPTH = MAX_DEPTH * 16;
const MAX_JSON_NODES = MAX_CANDIDATES * 2;
const MAX_JSON_STRINGS = MAX_CANDIDATES * 4;
const UTF8 = new TextDecoder("utf-8", { fatal: true });
const DISALLOWED_TEXT = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u;
const PATTERNS = [
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/i,
  /["']?private[_-]?key["']?\s*[:=]/i,
  /\bgh[pousr]_[A-Za-z0-9_]{20,255}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{20,255}\b/,
  /\bya29\.[A-Za-z0-9._-]{20,512}\b/,
  /\bAIza[0-9A-Za-z_-]{35}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,255}\b/,
  /\bxapp-[0-9]+-[A-Za-z0-9-]{10,255}\b/,
  /\bauthorization["']?\s*[:=]\s*["']?bearer\s+[A-Za-z0-9._~+/=-]{8,512}/i,
  /\bbearer\s+[A-Za-z0-9._~+/=-]{20,512}\b/i,
];

function hasCredential(value) {
  return PATTERNS.some((pattern) => pattern.test(value));
}

export function textLooksLikeCredential(value) {
  return typeof value === "string" && value.length > 0 && hasCredential(value);
}

function decodedUrl(value) {
  if (!value.includes("%") || value.length > MAX_INPUT) return null;
  const output = [];
  let changed = false;
  for (let index = 0; index < value.length;) {
    if (value[index] === "%" && /^[0-9a-f]{2}$/i.test(value.slice(index + 1, index + 3))) {
      output.push(Buffer.from([Number.parseInt(value.slice(index + 1, index + 3), 16)]));
      index += 3;
      changed = true;
      continue;
    }
    const character = String.fromCodePoint(value.codePointAt(index));
    output.push(Buffer.from(character, "utf8"));
    index += character.length;
  }
  return changed ? Buffer.concat(output) : null;
}

function jsonStrings(value) {
  const output = [];
  const stack = [{ value, depth: 0 }];
  let nodes = 0;
  const addString = (text, decimalLeaf = false) => {
    output.push({ text, decimalLeaf });
    if (output.length > MAX_JSON_STRINGS) throw new Error("CREDENTIAL_SCAN_LIMIT_EXCEEDED");
  };
  while (stack.length) {
    const current = stack.pop();
    nodes += 1;
    if (nodes > MAX_JSON_NODES || current.depth > MAX_JSON_DEPTH) {
      throw new Error("CREDENTIAL_SCAN_LIMIT_EXCEEDED");
    }
    if (typeof current.value === "string") {
      addString(current.value, /^\d+$/.test(current.value));
      continue;
    }
    if (!current.value || typeof current.value !== "object") continue;
    const keys = Object.keys(current.value).sort();
    for (const key of keys) addString(key);
    for (let index = keys.length - 1; index >= 0; index -= 1) {
      stack.push({ value: current.value[keys[index]], depth: current.depth + 1 });
    }
  }
  return output;
}

function decodedBase64(value) {
  if (value.length < 8 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(value)) return null;
  if (value.length > Math.ceil(MAX_SINGLE_DECODED * 4 / 3) + 4) {
    throw new Error("CREDENTIAL_SCAN_LIMIT_EXCEEDED");
  }
  const bytes = Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const standard = bytes.toString("base64");
  const canonical = standard === value || standard.replace(/=+$/, "") === value
    || bytes.toString("base64url") === value;
  if (!canonical) return null;
  if (bytes.length > MAX_SINGLE_DECODED) throw new Error("CREDENTIAL_SCAN_LIMIT_EXCEEDED");
  return bytes;
}

function base64Candidates(value) {
  return (value.match(/[A-Za-z0-9+/_-]{6,}={0,2}/g) ?? []).filter((candidate) => {
    if (candidate.length < 8) return false;
    if (/^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(candidate)) return false;
    if (/^\d+$/.test(candidate)) return false;
    if (candidate.length < 16 && (/^[a-z]+$/.test(candidate) || /^[A-Z]+$/.test(candidate))) return false;
    if (/^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)+$/.test(candidate)) return false;
    return !/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(candidate);
  });
}

function compressedPayload(bytes) {
  return (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b)
    || (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b
      && ((bytes[2] === 0x03 && bytes[3] === 0x04)
        || (bytes[2] === 0x05 && bytes[3] === 0x06)
        || (bytes[2] === 0x07 && bytes[3] === 0x08)))
    || (bytes.length >= 2 && (bytes[0] & 0x0f) === 8 && (bytes[0] >> 4) <= 7
      && ((bytes[0] << 8) + bytes[1]) % 31 === 0)
    || (bytes.length >= 3 && bytes[0] === 0x42 && bytes[1] === 0x5a && bytes[2] === 0x68)
    || (bytes.length >= 6 && bytes.subarray(0, 6).equals(Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])));
}

export function assertCredentialFreeBytes(bytes) {
  if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > MAX_INPUT) {
    throw new Error("credential scan input is invalid");
  }
  const queue = [{ bytes: Buffer.from(bytes), depth: 0, source: "raw", typedAuthority: true }];
  const seen = new Set();
  let candidates = 0;
  let decodedTotal = 0;
  const enqueue = (value, depth, source, typedAuthority = false) => {
    if (depth > MAX_DEPTH) throw new Error("CREDENTIAL_SCAN_LIMIT_EXCEEDED");
    decodedTotal += value.length;
    if (decodedTotal > MAX_TOTAL_DECODED) throw new Error("CREDENTIAL_SCAN_LIMIT_EXCEEDED");
    queue.push({ bytes: value, depth, source, typedAuthority });
  };
  while (queue.length) {
    const current = queue.shift();
    const bytesHash = createHash("sha256").update(current.bytes).digest("hex");
    const key = `${current.source}\0${current.typedAuthority ? "typed" : "untyped"}\0${bytesHash}`;
    if (seen.has(key)) continue;
    seen.add(key);
    let digestText;
    try { digestText = UTF8.decode(current.bytes); } catch { digestText = null; }
    const exactDigest = typeof digestText === "string" && (/^[a-f0-9]{40}$/.test(digestText)
      || /^[a-f0-9]{64}$/.test(digestText));
    const ordinaryTypedText = exactDigest || current.source === "json-decimal";
    if (!ordinaryTypedText && compressedPayload(current.bytes)) throw new Error("UNSUPPORTED_ENCODED_PAYLOAD");
    if (hasCredential(current.bytes.toString("latin1"))) throw new Error("credential-shaped material detected");
    if (ordinaryTypedText) continue;
    let text;
    try {
      text = UTF8.decode(current.bytes);
    } catch {
      if (current.source !== "raw" && current.source !== "base64") {
        throw new Error("UNSUPPORTED_ENCODED_PAYLOAD");
      }
      continue;
    }
    if (current.source !== "raw" && DISALLOWED_TEXT.test(text)) {
      if (current.source === "base64") continue;
      throw new Error("UNSUPPORTED_ENCODED_PAYLOAD");
    }
    if (hasCredential(text)) throw new Error("credential-shaped material detected");
    let parsed = false;
    let json;
    try {
      json = JSON.parse(text);
      parsed = true;
    } catch {
      // Non-JSON text is still scanned for URL and base64 encodings below.
    }
    if (parsed) {
      try {
        rejectDuplicateJsonKeys(text);
      } catch (error) {
        if (error?.message === "duplicate JSON key") throw new Error("duplicate JSON key");
        // JSON.parse may accept forms the strict duplicate-key walker rejects; still walk strings.
      }
      const strings = jsonStrings(json);
      const initialTypedTree = current.source === "raw" && current.depth === 0
        && current.typedAuthority;
      for (const { text: value, decimalLeaf } of strings) {
        enqueue(
          Buffer.from(value, "utf8"),
          current.depth + 1,
          decimalLeaf && initialTypedTree ? "json-decimal" : "json",
          decimalLeaf && initialTypedTree,
        );
      }
      continue;
    }
    const url = decodedUrl(text);
    if (url !== null) {
      enqueue(url, current.depth + 1, "url");
      continue;
    }
    for (const candidate of base64Candidates(text)) {
      candidates += 1;
      if (candidates > MAX_CANDIDATES) throw new Error("CREDENTIAL_SCAN_LIMIT_EXCEEDED");
      const decoded = decodedBase64(candidate);
      if (decoded !== null) enqueue(decoded, current.depth + 1, "base64");
    }
  }
  return true;
}

export function createCredentialScan(scope, artifacts) {
  if (!(artifacts instanceof Map) || artifacts.size < 1 || artifacts.size > 100) {
    throw new Error("credential scan artifacts are invalid");
  }
  const scanned = [];
  for (const [id, bytes] of [...artifacts].sort(([left], [right]) => left.localeCompare(right))) {
    if (typeof id !== "string" || !/^E[0-9]{3}$/.test(id) || !Buffer.isBuffer(bytes)) {
      throw new Error("credential scan artifacts are invalid");
    }
    assertCredentialFreeBytes(bytes);
    scanned.push({ id, sha256: createHash("sha256").update(bytes).digest("hex") });
  }
  return {
    outcome: "CLEAN",
    scanner: "KEYLESS_CREDENTIAL_SCAN_V1",
    scope_hash: createHash("sha256")
      .update("KEYLESS_CREDENTIAL_SCAN_SCOPE_V1\0")
      .update(canonicalJson({ scope, artifacts: scanned }))
      .digest("hex"),
    artifact_count: artifacts.size,
  };
}
