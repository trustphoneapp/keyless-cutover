import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import {
  createKeyProof,
  expectedKeyProofContext,
  issueKeyProofChallenge,
  verifyAndConsumeGoogleKeyProof,
  verifyGoogleKeyProof,
  verifyKeyProof,
  verifyStoredGoogleKeyProof,
} from "../src/key-proof.mjs";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
const privateKeyId = "a".repeat(40);
const serviceAccountKey = JSON.stringify({
  type: "service_account",
  client_email: "keyless-demo@example-project.iam.gserviceaccount.com",
  private_key_id: privateKeyId,
  private_key: privateKeyPem,
});
const context = {
  migration_id: "migration-001",
  challenge_id: "challenge-001",
  nonce: "nonce-001",
  issued_at: "2026-08-12T12:00:00Z",
  expires_at: "2026-08-12T12:05:00Z",
  owner_id: "987654321",
  repository_id: "123456789",
  workflow_path: ".github/workflows/deploy.yml",
  workflow_ref: "trustphoneapp/keyless-cutover/.github/workflows/deploy.yml@refs/heads/main",
  workflow_blob_sha: "a".repeat(40),
  head_sha: "b".repeat(40),
  run_id: "456789123",
  run_attempt: "1",
  actor_id: "111111111",
  triggering_actor: "security-reviewer",
  event_name: "workflow_dispatch",
  ref: "refs/heads/main",
  environment: "keyless-demo",
  runner_environment: "github-hosted",
};

test("key-proof workflow paths refuse dot and parent segments", () => {
  assert.throws(() => createKeyProof(serviceAccountKey, {
    ...context,
    workflow_path: ".github/workflows/../deploy.yml",
  }), /workflow_path/);
  assert.throws(() => createKeyProof(serviceAccountKey, {
    ...context,
    workflow_path: ".github/workflows/./deploy.yml",
  }), /workflow_path/);
  assert.throws(() => issueKeyProofChallenge({
    migration_id: context.migration_id,
    owner_id: context.owner_id,
    repository_id: context.repository_id,
    workflow_path: ".github/workflows/foo/../bar.yml",
    event_name: context.event_name,
    ref: context.ref,
    environment: context.environment,
    client_email: "keyless-demo@example-project.iam.gserviceaccount.com",
  }), /workflow_path/);
  assert.throws(() => createKeyProof(
    serviceAccountKey.replace('"type":"service_account"', '"type":"service_account","type":"service_account"'),
    context,
  ), /duplicate JSON keys/);
});

test("key-proof issue path refuses calendar-invalid RFC3339 timestamps", () => {
  assert.throws(() => createKeyProof(serviceAccountKey, {
    ...context,
    issued_at: "2026-02-30T12:00:00Z",
  }), /issued_at has an invalid format/);
  assert.throws(() => createKeyProof(serviceAccountKey, {
    ...context,
    expires_at: "2026-13-01T12:00:00Z",
  }), /expires_at has an invalid format/);
  assert.throws(() => createKeyProof(serviceAccountKey, {
    ...context,
    issued_at: "2026-08-12T12:00:00+00:00",
  }), /issued_at has an invalid format/);
});

test("proof binds the exact key and workflow context without exporting the private key", () => {
  const proof = createKeyProof(serviceAccountKey, context);
  const expected = { ...context, client_email: proof.client_email, private_key_id: proof.private_key_id };

  assert.equal(verifyKeyProof(proof, publicKeyPem, expected, new Date("2026-08-12T12:01:00Z")), true);
  assert.equal(proof.private_key_id, privateKeyId);
  assert.equal(JSON.stringify(proof).includes("PRIVATE KEY"), false);
  assert.equal(JSON.stringify(proof).includes(privateKeyPem), false);
});

test("tampered proof fails closed", () => {
  const proof = createKeyProof(serviceAccountKey, context);
  const expected = { ...context, client_email: proof.client_email, private_key_id: proof.private_key_id };
  const now = new Date("2026-08-12T12:01:00Z");

  assert.equal(verifyKeyProof({ ...proof, repository_id: "987654320" }, publicKeyPem, expected, now), false);
  assert.equal(verifyKeyProof({ ...proof, run_attempt: "2" }, publicKeyPem, expected, now), false);
  assert.equal(verifyKeyProof({ ...proof, workflow_path: ".github/workflows/other.yml" }, publicKeyPem, expected, now), false);
  assert.equal(verifyKeyProof({ ...proof, private_key_id: "c".repeat(40) }, publicKeyPem, expected, now), false);
  assert.equal(verifyKeyProof({ ...proof, signature: "not-a-signature" }, publicKeyPem, expected, now), false);
  assert.equal(verifyKeyProof(proof, publicKeyPem, { ...expected, nonce: "wrong" }, now), false);
  assert.equal(verifyKeyProof(proof, publicKeyPem, expected, new Date("2026-08-12T12:05:00Z")), false);
  assert.equal(verifyKeyProof({ ...proof, issued_at: "2026-08-12T12:00:00+00:00" }, publicKeyPem, expected, now), false);
  assert.equal(verifyKeyProof({ ...proof, expires_at: "2026-08-12T12:05:00.000+00:00" }, publicKeyPem, expected, now), false);
});

test("malformed input is rejected before signing", () => {
  assert.throws(
    () => createKeyProof(serviceAccountKey, { ...context, nonce: "bad\nnonce" }),
    /invalid format/,
  );
  assert.throws(
    () => createKeyProof("{}", context),
    /not a service-account key/,
  );
});

test("Google certificate lookup is bounded and keyed by the exact key ID", async () => {
  const proof = createKeyProof(serviceAccountKey, context);
  const expected = { ...context, client_email: proof.client_email, private_key_id: proof.private_key_id };
  const response = (body, ok = true) => {
    const text = typeof body === "string" ? body : JSON.stringify(body);
    return {
      ok,
      status: ok ? 200 : 500,
      headers: { get: (name) => name.toLowerCase() === "content-length" ? String(Buffer.byteLength(text)) : null },
      text: async () => text,
    };
  };
  const validFetch = async () => response(JSON.stringify({ [privateKeyId]: publicKeyPem }));

  assert.equal(
    await verifyGoogleKeyProof(proof, expected, validFetch, new Date("2026-08-12T12:01:00Z")),
    true,
  );
  assert.equal(
    await verifyGoogleKeyProof(
      proof,
      expected,
      async () => response(JSON.stringify({ ["c".repeat(40)]: publicKeyPem })),
      new Date("2026-08-12T12:01:00Z"),
    ),
    false,
  );
  await assert.rejects(
    verifyGoogleKeyProof(proof, expected, async () => response("{"), new Date("2026-08-12T12:01:00Z")),
    /not valid JSON/,
  );
  await assert.rejects(
    verifyGoogleKeyProof(
      proof,
      expected,
      async () => response(`{"${privateKeyId}":${JSON.stringify(publicKeyPem)},"${privateKeyId}":"x"}`),
      new Date("2026-08-12T12:01:00Z"),
    ),
    /duplicate JSON keys/,
  );
  await assert.rejects(
    verifyGoogleKeyProof(
      proof,
      expected,
      async () => ({
        ok: true,
        status: 200,
        headers: { get: (name) => name === "content-length" ? "2" : null },
        text: async () => JSON.stringify({ [privateKeyId]: publicKeyPem }),
      }),
      new Date("2026-08-12T12:01:00Z"),
    ),
    /Content-Length/,
  );
});

test("protocol consumes one authoritative challenge exactly once", async () => {
  const challenge = issueKeyProofChallenge({
    migration_id: context.migration_id,
    owner_id: context.owner_id,
    repository_id: context.repository_id,
    workflow_path: context.workflow_path,
    event_name: context.event_name,
    ref: context.ref,
    environment: context.environment,
    client_email: "keyless-demo@example-project.iam.gserviceaccount.com",
  }, new Date("2026-08-12T12:00:00Z"));
  const observed = {
    ...context,
    client_email: undefined,
    private_key_id: undefined,
  };
  assert.equal("private_key_id" in challenge, false);
  const expected = expectedKeyProofContext(challenge, observed, privateKeyId);
  const proof = createKeyProof(serviceAccountKey, expected);
  const googleKey = {
    name: `projects/-/serviceAccounts/${proof.client_email}/keys/${proof.private_key_id}`,
    keyType: "USER_MANAGED",
    keyAlgorithm: "KEY_ALG_RSA_2048",
    disabled: false,
  };
  const getGoogleKey = async () => googleKey;
  const fetchImpl = async () => {
    const body = JSON.stringify({ [privateKeyId]: publicKeyPem });
    return {
      ok: true,
      status: 200,
      headers: { get: (name) => name.toLowerCase() === "content-length" ? String(Buffer.byteLength(body)) : null },
      text: async () => body,
    };
  };
  let consumed = false;
  const consume = async () => {
    if (consumed) return false;
    consumed = true;
    return true;
  };
  const input = {
    proof,
    challenge,
    observed,
    getGoogleKey,
    fetchImpl,
    consume,
    now: new Date("2026-08-12T12:01:00Z"),
  };

  const results = await Promise.all([
    verifyAndConsumeGoogleKeyProof(input),
    verifyAndConsumeGoogleKeyProof(input),
  ]);
  assert.deepEqual(results.sort(), [false, true]);
  assert.equal(await verifyAndConsumeGoogleKeyProof(input), false);
  assert.equal(
    await verifyAndConsumeGoogleKeyProof({
      ...input,
      consume: async () => true,
      getGoogleKey: async () => ({ ...googleKey, disabled: true }),
    }),
    false,
  );
  assert.throws(
    () => expectedKeyProofContext(challenge, { ...observed, repository_id: "999" }, privateKeyId),
    /does not match/,
  );

  const challengeStore = {
    get: async (id) => id === challenge.challenge_id ? challenge : null,
    consume,
  };
  consumed = false;
  assert.equal(await verifyStoredGoogleKeyProof({
    proof,
    observed,
    challengeStore,
    getGoogleKey,
    fetchImpl,
    now: input.now,
  }), true);
  assert.equal(await verifyStoredGoogleKeyProof({
    proof: { ...proof, challenge_id: "missing" },
    observed,
    challengeStore,
    getGoogleKey,
    fetchImpl,
    now: input.now,
  }), false);
});
