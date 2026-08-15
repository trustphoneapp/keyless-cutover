import { createHash, verify } from "node:crypto";

import { canonicalJson } from "./evidence-artifact.mjs";
import { parseK0ReceiptBytes } from "./k0-receipt.mjs";
import { rejectDuplicateJsonKeys } from "./observation-time.mjs";

const K0_KMS_ALGORITHM = "RSA_SIGN_PKCS1_2048_SHA256";
const CREDENTIAL = /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"private_key"\s*:|ya29\.[A-Za-z0-9._-]+|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|xapp-[0-9]+-[A-Za-z0-9-]{10,}|bearer\s+[A-Za-z0-9._~+/=-]{20,})/i;

const KEY_VERSION = /^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/locations\/[A-Za-z0-9_-]{1,63}\/keyRings\/[A-Za-z0-9_-]{1,63}\/cryptoKeys\/[A-Za-z0-9_-]{1,63}\/cryptoKeyVersions\/[1-9]\d*$/;
const SIDECAR_FIELDS = new Set(["version", "name", "algorithm", "digest_sha256", "signature"]);
const TRUST_FIELDS = new Set(["key_version", "algorithm", "public_key"]);

function exactObject(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === fields.size
    && Object.keys(value).every((key) => fields.has(key));
}

function digest(receiptBytes) {
  return createHash("sha256").update(receiptBytes).digest();
}

function base64(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  const bytes = Buffer.from(value, "base64");
  return bytes.toString("base64") === value ? bytes : null;
}

// This only builds inert digest material. Authorization remains RECOLLECTION_REQUIRED.
export function createKmsSigningRequest(receiptBytes, pinnedKeyVersion) {
  if (!Buffer.isBuffer(receiptBytes)) throw new Error("receipt bytes are invalid");
  const bytes = Buffer.from(receiptBytes);
  parseK0ReceiptBytes(bytes);
  if (typeof pinnedKeyVersion !== "string" || !KEY_VERSION.test(pinnedKeyVersion)) {
    throw new Error("pinned KMS key version is invalid");
  }
  return Object.freeze({
    name: pinnedKeyVersion,
    digest: Object.freeze({ sha256: digest(bytes).toString("base64") }),
  });
}

// Signature validity never changes the receipt's RECOLLECTION_REQUIRED authorization.
export function verifyKmsSignature(receiptBytes, sidecarBytes, pinnedTrustAnchor) {
  parseK0ReceiptBytes(receiptBytes);
  if (!exactObject(pinnedTrustAnchor, TRUST_FIELDS)
      || !KEY_VERSION.test(pinnedTrustAnchor.key_version ?? "")
      || pinnedTrustAnchor.algorithm !== K0_KMS_ALGORITHM
      || pinnedTrustAnchor.public_key?.type !== "public"
      || pinnedTrustAnchor.public_key?.asymmetricKeyType !== "rsa"
      || pinnedTrustAnchor.public_key?.asymmetricKeyDetails?.modulusLength !== 2048) {
    throw new Error("pinned KMS trust anchor is invalid");
  }
  if (!Buffer.isBuffer(sidecarBytes) || !sidecarBytes.length || sidecarBytes.length > 16_384) {
    throw new Error("KMS signature sidecar bytes are invalid");
  }
  let sidecar;
  try {
    const text = sidecarBytes.toString("utf8");
    if (CREDENTIAL.test(text)) throw new Error("KMS signature sidecar contains credential-shaped material");
    rejectDuplicateJsonKeys(text);
    sidecar = JSON.parse(text);
  } catch (error) {
    if (error?.message === "duplicate JSON key") throw new Error("KMS signature sidecar contains duplicate JSON keys");
    if (/credential-shaped/.test(error?.message ?? "")) throw error;
    throw new Error("KMS signature sidecar is not JSON");
  }
  const expectedDigest = digest(receiptBytes).toString("base64");
  const signature = base64(sidecar?.signature);
  if (sidecarBytes.toString("utf8") !== canonicalJson(sidecar)
      || !exactObject(sidecar, SIDECAR_FIELDS) || sidecar.version !== 1
      || sidecar.name !== pinnedTrustAnchor.key_version
      || sidecar.algorithm !== pinnedTrustAnchor.algorithm
      || sidecar.digest_sha256 !== expectedDigest || signature?.length !== 256
      || !verify("sha256", receiptBytes, pinnedTrustAnchor.public_key, signature)) {
    throw new Error("KMS signature does not match the pinned trust anchor");
  }
  return true;
}
