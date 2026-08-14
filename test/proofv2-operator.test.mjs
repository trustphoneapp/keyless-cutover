import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import AdmZip from "adm-zip";

import { FirestoreChallengeStore } from "../src/firestore-challenge-store.mjs";
import { createKeyProof, expectedKeyProofContext } from "../src/key-proof.mjs";
import { collectProofV2, issueProofV2, proofV2DispatchInputs, verifyAndConsumeProofV2 } from "../src/proofv2-operator.mjs";

class MemoryFirestore {
  documents = new Map();
  transactionTail = Promise.resolve();
  collection() {
    return { doc: (id) => ({
      id,
      create: async (value) => {
        if (this.documents.has(id)) throw new Error("already exists");
        this.documents.set(id, structuredClone(value));
      },
      get: async () => this.snapshot(id),
    }) };
  }
  snapshot(id) {
    const value = this.documents.get(id);
    return { exists: value !== undefined, data: () => structuredClone(value) };
  }
  async runTransaction(callback) {
    let release;
    const previous = this.transactionTail;
    this.transactionTail = new Promise((resolve) => { release = resolve; });
    await previous;
    const updates = [];
    try {
      const result = await callback({
        get: async (reference) => this.snapshot(reference.id),
        update: (reference, patch) => updates.push([reference.id, patch]),
      });
      for (const [id, patch] of updates) this.documents.set(id, { ...this.documents.get(id), ...patch });
      return result;
    } finally {
      release();
    }
  }
}

const now = new Date("2026-08-13T23:20:00Z");
const scope = {
  migration_id: "k0-proofv2-reviewed",
  owner_id: "289479481",
  repository_id: "1332803088",
  workflow_path: ".github/workflows/k0-proof-v2.yml",
  event_name: "workflow_dispatch",
  ref: "refs/heads/main",
  environment: "production",
  client_email: "keyless-deploy@keyless-k0-20260813.iam.gserviceaccount.com",
};
const observed = {
  owner_id: scope.owner_id,
  repository_id: scope.repository_id,
  workflow_path: scope.workflow_path,
  workflow_ref: "trustphoneapp/keyless-cutover/.github/workflows/k0-proof-v2.yml@refs/heads/main",
  workflow_blob_sha: "a".repeat(40),
  head_sha: "b".repeat(40),
  run_id: "456789123",
  run_attempt: "1",
  actor_id: "289479481",
  triggering_actor: "trustphoneapp",
  event_name: "workflow_dispatch",
  ref: "refs/heads/main",
  environment: "production",
  runner_environment: "github-hosted",
};

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const privateKeyId = "c".repeat(40);
const serviceAccountKey = JSON.stringify({
  type: "service_account",
  client_email: scope.client_email,
  private_key_id: privateKeyId,
  private_key: privateKey.export({ type: "pkcs8", format: "pem" }),
});
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });

function response(status, value, extraHeaders = {}) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (name) => extraHeaders[name.toLowerCase()] ?? null },
    text: async () => bytes.toString("utf8"),
    arrayBuffer: async () => bytes,
  };
}

function githubFixture(proof, { artifacts = 1, approved = true, extraProofField = false } = {}) {
  const workflow = "name: K0 reviewed ProofV2\njobs:\n  proof:\n    runs-on: ubuntu-latest\n    environment: production\n";
  const zip = new AdmZip();
  zip.addFile("keyless-proof-v2.json", Buffer.from(JSON.stringify(extraProofField ? { ...proof, unexpected: true } : proof)));
  return async (url) => {
    if (url.endsWith("/actions/runs/456789123")) return response(200, {
      id: 456789123, run_attempt: 1, status: "completed", conclusion: "success",
      path: scope.workflow_path, head_sha: observed.head_sha, head_branch: "main", event: "workflow_dispatch",
      actor: { id: 289479481 }, triggering_actor: { login: "trustphoneapp" },
      repository: { id: Number(scope.repository_id), full_name: "trustphoneapp/keyless-cutover", owner: { id: Number(scope.owner_id) } },
    });
    if (url.includes("/contents/")) return response(200, {
      encoding: "base64", content: Buffer.from(workflow).toString("base64"), sha: observed.workflow_blob_sha,
    });
    if (url.endsWith("/approvals")) return response(200, approved ? [{
      state: "approved", user: { id: 214124322, login: "cherala2002" }, environments: [{ name: "production" }],
    }] : []);
    if (url.includes("/artifacts?")) return response(200, {
      artifacts: Array.from({ length: artifacts }, (_, index) => ({
        id: 88 + index, name: "keyless-proof-v2-456789123-1", expired: false,
      })),
    });
    if (/\/actions\/artifacts\/\d+\/zip$/.test(url)) return response(302, "", { location: "https://objects.githubusercontent.com/proofv2.zip" });
    if (url.endsWith("proofv2.zip")) return response(200, zip.toBuffer(), { "content-length": String(zip.toBuffer().length) });
    throw new Error(`unexpected URL ${url}`);
  };
}

test("operator issues only the five bounded dispatch fields", async () => {
  const store = new FirestoreChallengeStore({ firestore: new MemoryFirestore(), now: () => now });
  const { challenge, dispatch_inputs: dispatchInputs } = await issueProofV2({ challengeStore: store, scope });
  assert.deepEqual(dispatchInputs, proofV2DispatchInputs(challenge));
  assert.deepEqual(Object.keys(dispatchInputs), ["migration_id", "challenge_id", "nonce", "issued_at", "expires_at"]);
  assert.equal(challenge.status, "ISSUED");
  assert.equal("private_key_id" in challenge, false);
  assert.equal(Date.parse(challenge.expires_at) - Date.parse(challenge.issued_at), 5 * 60 * 1000);
});

test("operator independently collects, verifies, consumes, and rejects replay", async () => {
  const store = new FirestoreChallengeStore({ firestore: new MemoryFirestore(), now: () => now });
  const { challenge } = await issueProofV2({ challengeStore: store, scope });
  const proof = createKeyProof(serviceAccountKey, expectedKeyProofContext(challenge, observed, privateKeyId));
  const collected = await collectProofV2({
    owner: "trustphoneapp", repository: "keyless-cutover", runId: observed.run_id,
    workflowPath: scope.workflow_path, environment: "production", token: `gho_${"t".repeat(36)}`,
    fetchImpl: githubFixture(proof),
  });
  assert.deepEqual(collected.proof, proof);
  assert.equal(collected.artifact_name, "keyless-proof-v2-456789123-1");
  const receipt = await verifyAndConsumeProofV2({
    challengeStore: store,
    proof: collected.proof,
    observed: collected.observed,
    getGoogleKey: async () => ({
      name: `projects/-/serviceAccounts/${scope.client_email}/keys/${privateKeyId}`,
      keyType: "USER_MANAGED", keyAlgorithm: ["KEY_ALG", "RSA", "2048"].join("_"), disabled: false,
    }),
    fetchImpl: async () => response(200, { [privateKeyId]: publicKeyPem }),
    now: new Date("2026-08-13T23:21:00Z"),
  });
  assert.equal(receipt.verified, true);
  assert.equal(receipt.consumed, true);
  assert.equal(receipt.replay_rejected, true);
  assert.equal(receipt.recovered_after_consume, false);
  assert.equal(receipt.key_id, privateKeyId);
  assert.match(receipt.receipt_sha256, /^[a-f0-9]{64}$/);
  const recovered = await verifyAndConsumeProofV2({
    challengeStore: store,
    proof,
    observed,
    getGoogleKey: async () => ({
      name: `projects/-/serviceAccounts/${scope.client_email}/keys/${privateKeyId}`,
      keyType: "USER_MANAGED", keyAlgorithm: ["KEY_ALG", "RSA", "2048"].join("_"), disabled: false,
    }),
    fetchImpl: async () => response(200, { [privateKeyId]: publicKeyPem }),
    now: new Date("2026-08-13T23:22:00Z"),
  });
  assert.equal(recovered.recovered_after_consume, true);
  await assert.rejects(verifyAndConsumeProofV2({
    challengeStore: store,
    proof: { ...proof, signature: `${proof.signature}a` },
    observed,
    getGoogleKey: async () => ({}),
    now: new Date("2026-08-13T23:22:00Z"),
  }), /digest does not match/);
});

test("operator refuses absent review or ambiguous artifact evidence", async () => {
  const store = new FirestoreChallengeStore({ firestore: new MemoryFirestore(), now: () => now });
  const { challenge } = await issueProofV2({ challengeStore: store, scope });
  const proof = createKeyProof(serviceAccountKey, expectedKeyProofContext(challenge, observed, privateKeyId));
  const input = {
    owner: "trustphoneapp", repository: "keyless-cutover", runId: observed.run_id,
    workflowPath: scope.workflow_path, environment: "production", token: `ghs_${"t".repeat(36)}`,
  };
  await assert.rejects(collectProofV2({ ...input, fetchImpl: githubFixture(proof, { approved: false }) }), /approval/);
  await assert.rejects(collectProofV2({ ...input, fetchImpl: githubFixture(proof, { artifacts: 2 }) }), /ambiguous/);
  await assert.rejects(collectProofV2({ ...input, fetchImpl: githubFixture(proof, { extraProofField: true }) }), /fields/);
});
