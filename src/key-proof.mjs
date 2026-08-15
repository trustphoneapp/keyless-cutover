import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  randomUUID,
  sign,
  verify,
} from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { isRfc3339, timestampBefore, timestampNanoseconds } from "./rfc3339.mjs";
import { rejectDuplicateJsonKeys } from "./observation-time.mjs";
import { CREDENTIAL_SHAPED as CREDENTIAL } from "./credential-shaped.mjs";

const DOMAIN = "keyless-cutover/key-proof/v2";
const MAX_CHALLENGE_LIFETIME_MS = 5 * 60 * 1000;
const MAX_CHALLENGE_LIFETIME_NS = BigInt(MAX_CHALLENGE_LIFETIME_MS) * 1_000_000n;
const SERVICE_ACCOUNT_EMAIL = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;
const KEY_ID = /^[a-f0-9]{40}$/;
const REPOSITORY_ID = /^\d+$/;
const GIT_SHA = /^[a-f0-9]{40,64}$/;
const GITHUB_PATH = /^\.github\/workflows\/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,62}\/)*[A-Za-z0-9][A-Za-z0-9._-]{0,62}\.ya?ml$/;
const GITHUB_REF = /^refs\/[A-Za-z0-9._/-]+$/;
const GITHUB_LOGIN = /^[A-Za-z0-9-]{1,39}$/;
const RUNNER_ENVIRONMENT = /^(github-hosted|self-hosted)$/;
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
    rejectDuplicateJsonKeys(raw);
    key = JSON.parse(raw);
  } catch (error) {
    if (error?.message === "duplicate JSON key") {
      throw new Error("GCP_SERVICE_ACCOUNT_KEY contains duplicate JSON keys");
    }
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
  const issuedAt = required(input.issued_at, "issued_at");
  const expiresAt = required(input.expires_at, "expires_at");
  if (!isRfc3339(issuedAt)) throw new Error("issued_at has an invalid format");
  if (!isRfc3339(expiresAt)) throw new Error("expires_at has an invalid format");
  return {
    migration_id: required(input.migration_id, "migration_id"),
    challenge_id: required(input.challenge_id, "challenge_id"),
    nonce: required(input.nonce, "nonce"),
    issued_at: issuedAt,
    expires_at: expiresAt,
    owner_id: required(input.owner_id, "owner_id", REPOSITORY_ID),
    repository_id: required(input.repository_id, "repository_id", REPOSITORY_ID),
    workflow_path: required(input.workflow_path, "workflow_path", GITHUB_PATH),
    workflow_ref: required(input.workflow_ref, "workflow_ref"),
    workflow_blob_sha: required(input.workflow_blob_sha, "workflow_blob_sha", GIT_SHA),
    head_sha: required(input.head_sha, "head_sha", GIT_SHA),
    run_id: required(input.run_id, "run_id", REPOSITORY_ID),
    run_attempt: required(input.run_attempt, "run_attempt", REPOSITORY_ID),
    actor_id: required(input.actor_id, "actor_id", REPOSITORY_ID),
    triggering_actor: required(input.triggering_actor, "triggering_actor", GITHUB_LOGIN),
    event_name: required(input.event_name, "event_name"),
    ref: required(input.ref, "ref", GITHUB_REF),
    environment: required(input.environment, "environment"),
    runner_environment: required(input.runner_environment, "runner_environment", RUNNER_ENVIRONMENT),
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
    `actor_id=${value.actor_id}`,
    `triggering_actor=${value.triggering_actor}`,
    `event_name=${value.event_name}`,
    `ref=${value.ref}`,
    `environment=${value.environment}`,
    `runner_environment=${value.runner_environment}`,
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

export function issueKeyProofChallenge(scope, now = new Date()) {
  const issuedAt = new Date(now);
  const expiresAt = new Date(issuedAt.getTime() + MAX_CHALLENGE_LIFETIME_MS);
  if (!Number.isFinite(issuedAt.getTime())) throw new Error("challenge issue time is invalid");
  return {
    status: "ISSUED",
    migration_id: required(scope.migration_id, "migration_id"),
    challenge_id: randomUUID(),
    nonce: randomBytes(32).toString("base64url"),
    issued_at: issuedAt.toISOString(),
    expires_at: expiresAt.toISOString(),
    owner_id: required(scope.owner_id, "owner_id", REPOSITORY_ID),
    repository_id: required(scope.repository_id, "repository_id", REPOSITORY_ID),
    workflow_path: required(scope.workflow_path, "workflow_path", GITHUB_PATH),
    event_name: required(scope.event_name, "event_name"),
    ref: required(scope.ref, "ref", GITHUB_REF),
    environment: required(scope.environment, "environment"),
    client_email: required(scope.client_email, "client_email", SERVICE_ACCOUNT_EMAIL),
  };
}

export function expectedKeyProofContext(challenge, observed, claimedPrivateKeyId = challenge?.private_key_id) {
  if (challenge?.status !== "ISSUED") throw new Error("challenge is not issued");
  for (const name of ["owner_id", "repository_id", "workflow_path", "event_name", "ref", "environment"]) {
    if (observed?.[name] !== challenge[name]) throw new Error(`${name} does not match the challenge`);
  }
  return fields({
    ...challenge,
    workflow_ref: observed.workflow_ref,
    workflow_blob_sha: observed.workflow_blob_sha,
    head_sha: observed.head_sha,
    run_id: observed.run_id,
    run_attempt: observed.run_attempt,
    actor_id: observed.actor_id,
    triggering_actor: observed.triggering_actor,
    runner_environment: observed.runner_environment,
    private_key_id: required(claimedPrivateKeyId, "private_key_id", KEY_ID),
  });
}

export function verifyKeyProof(proof, publicKeyPem, expected, now = new Date()) {
  if (proof?.version !== 2 || proof?.algorithm !== "RS256" || !expected) return false;
  try {
    const message = canonicalMessage(proof);
    if (message !== canonicalMessage(expected)) return false;
    if (!isRfc3339(proof.issued_at) || !isRfc3339(proof.expires_at)) return false;
    const issuedAt = timestampNanoseconds(proof.issued_at);
    const expiresAt = timestampNanoseconds(proof.expires_at);
    const observedAt = timestampNanoseconds(now.toISOString());
    if (
      issuedAt === null
      || expiresAt === null
      || observedAt === null
      || !timestampBefore(proof.issued_at, proof.expires_at)
      || expiresAt - issuedAt > MAX_CHALLENGE_LIFETIME_NS
      || observedAt < issuedAt
      || observedAt >= expiresAt
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

export async function verifyGoogleKeyProof(proof, expected, fetchImpl = fetch, now = new Date()) {
  const clientEmail = required(proof?.client_email, "client_email", SERVICE_ACCOUNT_EMAIL);
  const keyId = required(proof?.private_key_id, "private_key_id", KEY_ID);
  const url = `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(clientEmail)}`;
  const response = await fetchImpl(url, {
    redirect: "error",
    signal: AbortSignal.timeout(5_000),
  });
  if (!response.ok) throw new Error(`Google public-key lookup failed with HTTP ${response.status}`);
  const declared = response.headers?.get?.("content-length") ?? null;
  if (declared === null || typeof declared !== "string" || declared.length > 16
      || !/^\d+$/.test(declared) || Number(declared) > 256_000) {
    throw new Error(declared === null
      ? "Google public-key lookup response is missing Content-Length"
      : "Google public-key lookup response is too large");
  }
  const body = await response.text();
  if (Buffer.byteLength(body) > 256_000) throw new Error("Google public-key lookup response is too large");
  if (Buffer.byteLength(body) !== Number(declared)) {
    throw new Error("Google public-key lookup response length does not match Content-Length");
  }
  if (CREDENTIAL.test(body)) throw new Error("Google public-key lookup response contains credential-shaped material");
  let certificates;
  try {
    rejectDuplicateJsonKeys(body);
    certificates = JSON.parse(body);
  } catch (error) {
    if (error?.message === "duplicate JSON key") {
      throw new Error("Google public-key lookup response contains duplicate JSON keys");
    }
    throw new Error("Google public-key lookup response is not valid JSON");
  }
  if (!certificates || typeof certificates !== "object" || Array.isArray(certificates)) {
    throw new Error("Google public-key lookup response is invalid");
  }
  const certificate = certificates[keyId];
  if (typeof certificate !== "string") return false;
  return verifyKeyProof(proof, certificate, expected, now);
}

function googleKeyMatches(googleKey, expected) {
  if (typeof googleKey?.name !== "string") return false;
  const match = googleKey.name.match(/^projects\/[^/]+\/serviceAccounts\/([^/]+)\/keys\/([^/]+)$/);
  if (!match) return false;
  let account;
  try {
    account = decodeURIComponent(match[1]);
  } catch {
    return false;
  }
  return (
    account === expected.client_email &&
    match[2] === expected.private_key_id &&
    googleKey.keyType === "USER_MANAGED" &&
    googleKey.keyAlgorithm === "KEY_ALG_RSA_2048" &&
    googleKey.disabled === false
  );
}

export async function verifyGoogleKeyProofAuthority({
  proof,
  challenge,
  observed,
  getGoogleKey,
  fetchImpl = fetch,
  now = new Date(),
}) {
  if (typeof getGoogleKey !== "function") throw new Error("an authenticated Google key reader is required");
  if (!challenge || !["ISSUED", "CONSUMED"].includes(challenge.status)) {
    throw new Error("challenge status is invalid");
  }
  const expected = expectedKeyProofContext({ ...challenge, status: "ISSUED" }, observed, proof?.private_key_id);
  const googleKey = await getGoogleKey({
    client_email: expected.client_email,
    private_key_id: expected.private_key_id,
  });
  if (!googleKeyMatches(googleKey, expected)) return false;
  return verifyGoogleKeyProof(proof, expected, fetchImpl, now);
}

export async function verifyAndConsumeGoogleKeyProof({
  proof,
  challenge,
  observed,
  getGoogleKey,
  fetchImpl = fetch,
  consume,
  now = new Date(),
}) {
  if (typeof consume !== "function") throw new Error("an atomic challenge consumer is required");
  if (challenge?.status !== "ISSUED") throw new Error("challenge is not issued");
  if (!await verifyGoogleKeyProofAuthority({ proof, challenge, observed, getGoogleKey, fetchImpl, now })) return false;
  return (await consume({
    challenge_id: challenge.challenge_id,
    expected_status: "ISSUED",
    consumed_status: "CONSUMED",
    proof_digest: keyProofDigest(proof),
  })) === true;
}

export async function verifyStoredGoogleKeyProof({
  proof,
  observed,
  challengeStore,
  getGoogleKey,
  fetchImpl = fetch,
  now = new Date(),
}) {
  if (typeof challengeStore?.get !== "function" || typeof challengeStore?.consume !== "function") {
    throw new Error("an authoritative challenge store is required");
  }
  const challengeId = required(proof?.challenge_id, "challenge_id");
  const challenge = await challengeStore.get(challengeId);
  if (!challenge) return false;
  return verifyAndConsumeGoogleKeyProof({
    proof,
    challenge,
    observed,
    getGoogleKey,
    fetchImpl,
    consume: (transition) => challengeStore.consume(transition),
    now,
  });
}

export function keyProofDigest(proof) {
  return createHash("sha256")
    .update(JSON.stringify(proof, Object.keys(proof).sort()))
    .digest("hex");
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
    actor_id: process.env.GITHUB_ACTOR_ID,
    triggering_actor: process.env.GITHUB_TRIGGERING_ACTOR,
    event_name: process.env.GITHUB_EVENT_NAME,
    ref: process.env.GITHUB_REF,
    environment: process.env.KEYLESS_ENVIRONMENT,
    runner_environment: process.env.RUNNER_ENVIRONMENT,
  });
  const output = resolve(outPath);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(proof, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  process.stdout.write(`Key proof written to ${output}\n`);
}

async function verifyFile(proofPath, expectedPath, certificatePath) {
  const proofText = await readFile(resolve(proofPath), "utf8");
  const expectedText = await readFile(resolve(expectedPath), "utf8");
  let proof;
  let expected;
  try {
    rejectDuplicateJsonKeys(proofText);
    proof = JSON.parse(proofText);
    rejectDuplicateJsonKeys(expectedText);
    expected = JSON.parse(expectedText);
  } catch (error) {
    if (error?.message === "duplicate JSON key") throw new Error("key-proof verify input contains duplicate JSON keys");
    throw new Error("key-proof verify input is not valid JSON");
  }
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
