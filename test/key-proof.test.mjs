import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import { createKeyProof, verifyKeyProof } from "../src/key-proof.mjs";

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
  event_name: "workflow_dispatch",
  ref: "refs/heads/main",
  environment: "keyless-demo",
};

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
