import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const DOMAIN = "keyless-cutover/key-proof/v2";
const MAX_CHALLENGE_LIFETIME_MS = 5 * 60 * 1000;
const SERVICE_ACCOUNT_EMAIL = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;
const KEY_ID = /^[a-f0-9]{40}$/;
const REPOSITORY_ID = /^\d+$/;
const GIT_SHA = /^[a-f0-9]{40,64}$/;
const GITHUB_PATH = /^\.github\/workflows\/[A-Za-z0-9._/-]+\.ya?ml$/;
const GITHUB_REF = /^refs\/[A-Za-z0-9._/-]+$/;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

function required(value, name, pattern) {
  if (typeof value !== "string" || !value || value.length > 512) {
    throw new Error(`${name} must be a non-empty string of at most 512 characters`);
  }
  if (/[\r\n]/.test(value) || (pattern && !pattern.test(value))) {
    throw new Error(`${name} has an invalid format`);
  }
  return value;
}

function privateKeyPem(value) {
  if (
    typeof value !== "string" ||
    value.length > 16_384 ||
    !/^-----BEGIN PRIVATE KEY-----\r?\n[\s\S]+\r?\n-----END PRIVATE KEY-----\r?\n?$/.test(value)
  ) {
    throw new Error("private_key is not a valid bounded PKCS#8 PEM");
  }
  return value;
}

function parseServiceAccountKey(raw) {
  let key;
  try {
    key = JSON.parse(raw);
  } catch {
    throw new Error("GCP_SERVICE_ACCOUNT_KEY is not valid JSON");
  }
  if (key.type !== "service_account") {
    throw new Error("GCP_SERVICE_ACCOUNT_KEY is not a service-account key");
  }
  return {
    clientEmail: required(key.client_email, "client_email", SERVICE_ACCOUNT_EMAIL),
    privateKeyId: required(key.private_key_id, "private_key_id", KEY_ID),
    privateKey: privateKeyPem(key.private_key),
  };
}

function fields(input) {
  return {
    migration_id: required(input.migration_id, "migration_id"),
    challenge_id: required(input.challenge_id, "challenge_id"),
    nonce: required(input.nonce, "nonce"),
    issued_at: required(input.issued_at, "issued_at", ISO_TIMESTAMP),
    expires_at: required(input.expires_at, "expires_at", ISO_TIMESTAMP),
    owner_id: required(input.owner_id, "owner_id", REPOSITORY_ID),
    repository_id: required(input.repository_id, "repository_id", REPOSITORY_ID),
    workflow_path: required(input.workflow_path, "workflow_path", GITHUB_PATH),
    workflow_ref: required(input.workflow_ref, "workflow_ref"),
    workflow_blob_sha: required(input.workflow_blob_sha, "workflow_blob_sha", GIT_SHA),
    head_sha: required(input.head_sha, "head_sha", GIT_SHA),
    run_id: required(input.run_id, "run_id", REPOSITORY_ID),
    run_attempt: required(input.run_attempt, "run_attempt", REPOSITORY_ID),
    event_name: required(input.event_name, "event_name"),
    ref: required(input.ref, "ref", GITHUB_REF),
    environment: required(input.environment, "environment"),
    client_email: required(input.client_email, "client_email", SERVICE_ACCOUNT_EMAIL),
    private_key_id: required(input.private_key_id, "private_key_id", KEY_ID),
  };
}

export function canonicalMessage(input) {
  const value = fields(input);
  return [
    DOMAIN,
    `migration_id=${value.migration_id}`,
    `challenge_id=${value.challenge_id}`,
    `nonce=${value.nonce}`,
    `issued_at=${value.issued_at}`,
    `expires_at=${value.expires_at}`,
    `owner_id=${value.owner_id}`,
    `repository_id=${value.repository_id}`,
    `workflow_path=${value.workflow_path}`,
    `workflow_ref=${value.workflow_ref}`,
    `workflow_blob_sha=${value.workflow_blob_sha}`,
    `head_sha=${value.head_sha}`,
    `run_id=${value.run_id}`,
    `run_attempt=${value.run_attempt}`,
    `event_name=${value.event_name}`,
    `ref=${value.ref}`,
    `environment=${value.environment}`,
    `client_email=${value.client_email}`,
    `private_key_id=${value.private_key_id}`,
  ].join("\n");
}

export function createKeyProof(serviceAccountKeyJson, context) {
  const key = parseServiceAccountKey(serviceAccountKeyJson);
  const proofFields = fields({
    ...context,
    client_email: key.clientEmail,
    private_key_id: key.privateKeyId,
  });
  const message = canonicalMessage(proofFields);
  const privateKey = createPrivateKey(key.privateKey);
  const signature = sign("sha256", Buffer.from(message), privateKey).toString("base64url");

  return {
    version: 2,
    algorithm: "RS256",
    ...proofFields,
    message_sha256: createHash("sha256").update(message).digest("hex"),
    signature,
  };
}

export function verifyKeyProof(proof, publicKeyPem, expected, now = new Date()) {
  if (proof?.version !== 2 || proof?.algorithm !== "RS256" || !expected) return false;
  try {
    const message = canonicalMessage(proof);
    if (message !== canonicalMessage(expected)) return false;
    const issuedAt = Date.parse(proof.issued_at);
    const expiresAt = Date.parse(proof.expires_at);
    const observedAt = now.getTime();
    if (
      !Number.isFinite(issuedAt) ||
      !Number.isFinite(expiresAt) ||
      expiresAt <= issuedAt ||
      expiresAt - issuedAt > MAX_CHALLENGE_LIFETIME_MS ||
      observedAt < issuedAt ||
      observedAt >= expiresAt
    ) {
      return false;
    }
    const digest = createHash("sha256").update(message).digest("hex");
    if (digest !== proof.message_sha256) return false;
    return verify(
      "sha256",
      Buffer.from(message),
      createPublicKey(publicKeyPem),
      Buffer.from(required(proof.signature, "signature"), "base64url"),
    );
  } catch {
    return false;
  }
}

export async function verifyGoogleKeyProof(proof, expected, fetchImpl = fetch) {
  const clientEmail = required(proof?.client_email, "client_email", SERVICE_ACCOUNT_EMAIL);
  const keyId = required(proof?.private_key_id, "private_key_id", KEY_ID);
  const url = `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(clientEmail)}`;
  const response = await fetchImpl(url, {
    redirect: "error",
    signal: AbortSignal.timeout(5_000),
  });
  if (!response.ok) throw new Error(`Google public-key lookup failed with HTTP ${response.status}`);
  const body = await response.text();
  if (body.length > 256_000) throw new Error("Google public-key lookup response is too large");
  const certificates = JSON.parse(body);
  const certificate = certificates[keyId];
  if (typeof certificate !== "string") return false;
  return verifyKeyProof(proof, certificate, expected);
}

async function generate(outPath) {
  const rawKey = process.env.GCP_SERVICE_ACCOUNT_KEY;
  if (!rawKey) throw new Error("GCP_SERVICE_ACCOUNT_KEY is required");
  const proof = createKeyProof(rawKey, {
    migration_id: process.env.KEYLESS_MIGRATION_ID,
    challenge_id: process.env.KEYLESS_CHALLENGE_ID,
    nonce: process.env.KEYLESS_NONCE,
    issued_at: process.env.KEYLESS_ISSUED_AT,
    expires_at: process.env.KEYLESS_EXPIRES_AT,
    owner_id: process.env.GITHUB_REPOSITORY_OWNER_ID,
    repository_id: process.env.GITHUB_REPOSITORY_ID,
    workflow_path: process.env.KEYLESS_WORKFLOW_PATH,
    workflow_ref: process.env.GITHUB_WORKFLOW_REF,
    workflow_blob_sha: process.env.KEYLESS_WORKFLOW_BLOB_SHA,
    head_sha: process.env.GITHUB_SHA,
    run_id: process.env.GITHUB_RUN_ID,
    run_attempt: process.env.GITHUB_RUN_ATTEMPT,
    event_name: process.env.GITHUB_EVENT_NAME,
    ref: process.env.GITHUB_REF,
    environment: process.env.KEYLESS_ENVIRONMENT,
  });
  const output = resolve(outPath);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(proof, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  process.stdout.write(`Key proof written to ${output}\n`);
}

async function verifyFile(proofPath, expectedPath, certificatePath) {
  const proof = JSON.parse(await readFile(resolve(proofPath), "utf8"));
  const expected = JSON.parse(await readFile(resolve(expectedPath), "utf8"));
  const valid = certificatePath
    ? verifyKeyProof(proof, await readFile(resolve(certificatePath), "utf8"), expected)
    : await verifyGoogleKeyProof(proof, expected);
  if (!valid) throw new Error("Key proof verification failed");
  process.stdout.write(`Verified key ${proof.private_key_id} for ${proof.client_email}\n`);
}

async function main([command, ...args]) {
  if (command === "generate" && args[0]) return generate(args[0]);
  if (command === "verify" && args[0] && args[1]) return verifyFile(args[0], args[1], args[2]);
  throw new Error(
    "Usage: node src/key-proof.mjs generate <proof.json> | verify <proof.json> <expected.json> [certificate.pem]",
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
