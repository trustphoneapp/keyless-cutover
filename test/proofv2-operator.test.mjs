import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import AdmZip from "adm-zip";

import { canonicalJson } from "../src/evidence-artifact.mjs";
import { FirestoreChallengeStore } from "../src/firestore-challenge-store.mjs";
import { createKeyProof, expectedKeyProofContext, keyProofDigest } from "../src/key-proof.mjs";
import {
  collectProofV2,
  collectReadOnlyConsumedProofV2State,
  issueProofV2,
  proofV2DispatchInputs,
  verifyAndConsumeProofV2,
} from "../src/proofv2-operator.mjs";

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
  started_at: "2026-08-13T23:20:30Z",
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
  return new Response(bytes, {
    status,
    headers: {
      "content-length": String(bytes.length),
      date: "Thu, 13 Aug 2026 23:21:00 GMT",
      ...extraHeaders,
    },
  });
}

function githubFixture(proof, {
  artifacts = 1,
  artifactTotalCount = artifacts,
  omitArtifactTotalCount = false,
  approved = true,
  extraProofField = false,
} = {}) {
  const workflow = "name: K0 reviewed ProofV2\njobs:\n  proof:\n    runs-on: ubuntu-latest\n    environment: production\n";
  const zip = new AdmZip();
  zip.addFile("keyless-proof-v2.json", Buffer.from(JSON.stringify(extraProofField ? { ...proof, unexpected: true } : proof)));
  return async (url) => {
    if (url.endsWith("/actions/runs/456789123")) return response(200, {
      id: 456789123, run_attempt: 1, status: "completed", conclusion: "success",
      path: scope.workflow_path, head_sha: observed.head_sha, head_branch: "main", event: "workflow_dispatch",
      run_started_at: "2026-08-13T23:20:30Z",
      actor: { id: 289479481 }, triggering_actor: { login: "trustphoneapp" },
      repository: { id: Number(scope.repository_id), full_name: "trustphoneapp/keyless-cutover", owner: { id: Number(scope.owner_id) } },
    });
    if (url.includes("/contents/")) return response(200, {
      encoding: "base64", content: Buffer.from(workflow).toString("base64"), sha: observed.workflow_blob_sha,
    });
    if (url.endsWith("/approvals")) return response(200, approved ? [{
      state: "approved", user: { id: 214124322, login: "cherala2002" }, environments: [{ name: "production" }],
    }] : []);
    if (url.includes("/jobs?")) return response(200, { total_count: 1, jobs: [{
      id: 77, name: "proof", status: "completed", conclusion: "success",
      started_at: "2026-08-13T23:20:31Z", completed_at: "2026-08-13T23:20:50Z",
      runner_group_name: "GitHub Actions", labels: ["ubuntu-latest"],
    }] });
    if (url.includes("/artifacts?")) {
      const value = { artifacts: Array.from({ length: artifacts }, (_, index) => ({
        id: 88 + index, name: "keyless-proof-v2-456789123-1", expired: false,
      })) };
      if (!omitArtifactTotalCount) value.total_count = artifactTotalCount;
      return response(200, value);
    }
    if (/\/actions\/artifacts\/\d+\/zip$/.test(url)) return response(302, "", { location: "https://objects.githubusercontent.com/proofv2.zip" });
    if (url.endsWith("proofv2.zip")) return response(200, zip.toBuffer(), { "content-length": String(zip.toBuffer().length) });
    throw new Error(`unexpected URL ${url}`);
  };
}

async function readOnlyFixture() {
  let storeNow = now;
  const store = new FirestoreChallengeStore({ firestore: new MemoryFirestore(), now: () => storeNow });
  const { challenge } = await issueProofV2({ challengeStore: store, scope });
  const proof = createKeyProof(serviceAccountKey, expectedKeyProofContext(challenge, observed, privateKeyId));
  storeNow = new Date("2026-08-13T23:21:00Z");
  const receipt = await verifyAndConsumeProofV2({
    challengeStore: store,
    proof,
    observed,
    getGoogleKey: async () => ({
      name: `projects/-/serviceAccounts/${scope.client_email}/keys/${privateKeyId}`,
      keyType: "USER_MANAGED", keyAlgorithm: "KEY_ALG_RSA_2048", disabled: false,
    }),
    fetchImpl: async () => response(200, { [privateKeyId]: publicKeyPem }),
    now: storeNow,
  });
  const consumed = await store.get(challenge.challenge_id);
  return {
    proof,
    receipt,
    receiptBytes: Buffer.from(canonicalJson(receipt)),
    state: {
      ...consumed,
      update_time: "2026-08-13T23:21:01.000Z",
      read_time: "2026-08-13T23:21:02.000Z",
    },
  };
}

function googleKey(keyId = privateKeyId) {
  return {
    name: `projects/-/serviceAccounts/${scope.client_email}/keys/${keyId}`,
    keyType: "USER_MANAGED", keyAlgorithm: "KEY_ALG_RSA_2048", disabled: false,
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
  let storeNow = now;
  const store = new FirestoreChallengeStore({ firestore: new MemoryFirestore(), now: () => storeNow });
  const { challenge } = await issueProofV2({ challengeStore: store, scope });
  const proof = createKeyProof(serviceAccountKey, expectedKeyProofContext(challenge, observed, privateKeyId));
  const collected = await collectProofV2({
    owner: "trustphoneapp", repository: "keyless-cutover", runId: observed.run_id,
    workflowPath: scope.workflow_path, environment: "production", token: `gho_${"t".repeat(36)}`,
    fetchImpl: githubFixture(proof),
  });
  assert.deepEqual(collected.proof, proof);
  assert.equal(collected.artifact_name, "keyless-proof-v2-456789123-1");
  storeNow = new Date("2026-08-13T23:21:00Z");
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
  assert.equal(receipt.version, 2);
  assert.equal(receipt.consumed_at, "2026-08-13T23:21:00.000Z");
  assert.doesNotThrow(() => JSON.parse(canonicalJson(receipt)));
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

test("operator rejects incomplete and over-bound ProofV2 artifact pages", async () => {
  const store = new FirestoreChallengeStore({ firestore: new MemoryFirestore(), now: () => now });
  const { challenge } = await issueProofV2({ challengeStore: store, scope });
  const proof = createKeyProof(serviceAccountKey, expectedKeyProofContext(challenge, observed, privateKeyId));
  const input = {
    owner: "trustphoneapp", repository: "keyless-cutover", runId: observed.run_id,
    workflowPath: scope.workflow_path, environment: "production", token: `ghs_${"t".repeat(36)}`,
  };
  for (const options of [
    { omitArtifactTotalCount: true },
    { artifactTotalCount: 2 },
    { artifacts: 101 },
  ]) {
    await assert.rejects(
      collectProofV2({ ...input, fetchImpl: githubFixture(proof, options) }),
      /incomplete or unbounded/,
    );
  }
});

test("read-only ProofV2 recollection binds the original receipt and performs no mutation", async () => {
  const fixture = await readOnlyFixture();
  const calls = { observe: 0, getKey: 0, fetch: 0, mutation: 0 };
  const challengeStore = {
    observe: async (challengeId) => {
      calls.observe += 1;
      assert.equal(challengeId, fixture.proof.challenge_id);
      return structuredClone(fixture.state);
    },
    issue: async () => { calls.mutation += 1; throw new Error("mutation called"); },
    consume: async () => { calls.mutation += 1; throw new Error("mutation called"); },
    get: async () => { calls.mutation += 1; throw new Error("weaker read called"); },
  };
  const result = await collectReadOnlyConsumedProofV2State({
    challengeStore,
    proof: fixture.proof,
    observed,
    operatorReceiptBytes: fixture.receiptBytes,
    getGoogleKey: async () => { calls.getKey += 1; return googleKey(); },
    fetchImpl: async () => { calls.fetch += 1; return response(200, { [privateKeyId]: publicKeyPem }); },
  });
  assert.equal(result.observedAt, fixture.state.read_time);
  assert.equal(result.challengeState.version, 3);
  assert.equal(result.challengeState.replay_evidence, "ORIGINAL_OPERATOR_RECEIPT_ONLY");
  assert.equal(result.challengeState.receipt_sha256.length, 64);
  assert.deepEqual(calls, { observe: 1, getKey: 1, fetch: 1, mutation: 0 });
  assert.equal(/private|signature|nonce/.test(JSON.stringify(result)), false);
});

test("read-only ProofV2 recollection rejects receipt, state, proof, run, key, and signature drift", async () => {
  const fixture = await readOnlyFixture();
  const collect = (overrides = {}) => collectReadOnlyConsumedProofV2State({
    challengeStore: { observe: async () => structuredClone(overrides.state ?? fixture.state) },
    proof: overrides.proof ?? fixture.proof,
    observed: overrides.observed ?? observed,
    operatorReceiptBytes: overrides.receiptBytes ?? fixture.receiptBytes,
    getGoogleKey: overrides.getGoogleKey ?? (async () => googleKey()),
    fetchImpl: overrides.fetchImpl ?? (async () => response(200, { [privateKeyId]: publicKeyPem })),
  });
  const missingField = structuredClone(fixture.receipt);
  delete missingField.environment;
  await assert.rejects(() => collect({ receiptBytes: Buffer.from(canonicalJson(missingField)) }), /receipt/);
  await assert.rejects(() => collect({
    receiptBytes: Buffer.from(canonicalJson({ ...fixture.receipt, replay_rejected: false })),
  }), /receipt/);
  await assert.rejects(() => collect({
    receiptBytes: Buffer.from(canonicalJson({ ...fixture.receipt, version: 1 })),
  }), /receipt/);
  await assert.rejects(() => collect({ receiptBytes: Buffer.concat([Buffer.from(" "), fixture.receiptBytes]) }), /canonical/);
  await assert.rejects(() => collect({
    receiptBytes: Buffer.from(fixture.receiptBytes.toString("utf8").replace('"version":2', '"version":2,"version":2')),
  }), /duplicate JSON keys/);
  await assert.rejects(() => collect({ state: { ...fixture.state, proof_digest: "f".repeat(64) } }), /state/);
  await assert.rejects(() => collect({ state: { ...fixture.state, owner_id: "999" } }), /state/);
  await assert.rejects(() => collect({ proof: { ...fixture.proof, run_id: "999" } }), /receipt/);
  await assert.rejects(() => collect({ observed: { ...observed, head_sha: "f".repeat(40) } }), /verification/);
  const { publicKey: wrongPublicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  await assert.rejects(() => collect({
    fetchImpl: async () => response(200, {
      [privateKeyId]: wrongPublicKey.export({ type: "spki", format: "pem" }),
    }),
  }), /verification/);

  const replacement = fixture.proof.signature.startsWith("A") ? "B" : "A";
  const badProof = { ...fixture.proof, signature: `${replacement}${fixture.proof.signature.slice(1)}` };
  const badDigest = keyProofDigest(badProof);
  const badReceipt = { ...fixture.receipt, proof_digest: badDigest };
  await assert.rejects(() => collect({
    proof: badProof,
    state: { ...fixture.state, proof_digest: badDigest },
    receiptBytes: Buffer.from(canonicalJson(badReceipt)),
  }), /verification/);
});

test("read-only ProofV2 recollection snapshots receipt, proof, and run before awaiting", async () => {
  const fixture = await readOnlyFixture();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const receiptBytes = Buffer.from(fixture.receiptBytes);
  const proof = structuredClone(fixture.proof);
  const run = structuredClone(observed);
  const pending = collectReadOnlyConsumedProofV2State({
    challengeStore: { observe: async () => { await gate; return structuredClone(fixture.state); } },
    proof,
    observed: run,
    operatorReceiptBytes: receiptBytes,
    getGoogleKey: async () => googleKey(),
    fetchImpl: async () => response(200, { [privateKeyId]: publicKeyPem }),
  });
  receiptBytes.fill(0);
  proof.signature = "mutated";
  run.head_sha = "f".repeat(40);
  release();
  assert.equal((await pending).challengeState.verified, true);
});

test("read-only ProofV2 recollection isolates the observed projection before later awaits", async () => {
  const fixture = await readOnlyFixture();
  const original = structuredClone(fixture.state);
  for (const mutateDuring of ["key", "certificate"]) {
    const retained = structuredClone(fixture.state);
    const calls = { observe: 0, mutation: 0 };
    const mutateRetained = () => Object.assign(retained, {
      owner_id: "999",
      repository_id: "998",
      proof_digest: "f".repeat(64),
      consumed_at: "2026-08-13T23:22:00Z",
      update_time: "2026-08-13T23:20:00Z",
      read_time: "2026-08-13T23:19:00Z",
      status: "ISSUED",
    });
    const result = await collectReadOnlyConsumedProofV2State({
      challengeStore: {
        observe: async () => { calls.observe += 1; return retained; },
        issue: async () => { calls.mutation += 1; },
        consume: async () => { calls.mutation += 1; },
      },
      proof: fixture.proof,
      observed,
      operatorReceiptBytes: fixture.receiptBytes,
      getGoogleKey: async () => {
        if (mutateDuring === "key") mutateRetained();
        return googleKey();
      },
      fetchImpl: async () => {
        if (mutateDuring === "certificate") mutateRetained();
        return response(200, { [privateKeyId]: publicKeyPem });
      },
    });
    assert.equal(result.observedAt, original.read_time);
    assert.equal(result.challengeState.owner_id, original.owner_id);
    assert.equal(result.challengeState.repository_id, original.repository_id);
    assert.equal(result.challengeState.proof_digest, original.proof_digest);
    assert.equal(result.challengeState.consumed_at, original.consumed_at);
    assert.equal(result.challengeState.update_time, original.update_time);
    assert.deepEqual(calls, { observe: 1, mutation: 0 });
  }
});

test("read-only ProofV2 recollection rejects nested, inherited, accessor, and Proxy projections", async () => {
  const fixture = await readOnlyFixture();
  let accessorReads = 0;
  const accessor = structuredClone(fixture.state);
  Object.defineProperty(accessor, "owner_id", {
    enumerable: true,
    get: () => {
      accessorReads += 1;
      return accessorReads === 1 ? fixture.state.owner_id : "999";
    },
  });
  const inherited = Object.assign(Object.create({ promoted: true }), fixture.state);
  const nested = { ...fixture.state, owner_id: { value: fixture.state.owner_id } };
  const proxied = new Proxy(structuredClone(fixture.state), {});
  const symbolField = structuredClone(fixture.state);
  symbolField[Symbol("hidden")] = "unexpected";
  for (const state of [nested, inherited, accessor, proxied, symbolField]) {
    let keyReads = 0;
    await assert.rejects(() => collectReadOnlyConsumedProofV2State({
      challengeStore: { observe: async () => state },
      proof: fixture.proof,
      observed,
      operatorReceiptBytes: fixture.receiptBytes,
      getGoogleKey: async () => { keyReads += 1; return googleKey(); },
      fetchImpl: async () => response(200, { [privateKeyId]: publicKeyPem }),
    }), /projection/);
    assert.equal(keyReads, 0);
  }
  assert.equal(accessorReads, 0);
});

test("ProofV2 issue refuses non-dispatch or non-production scopes", async () => {
  const store = new FirestoreChallengeStore({ firestore: new MemoryFirestore(), now: () => now });
  await assert.rejects(() => issueProofV2({
    challengeStore: store,
    scope: { ...scope, event_name: "push" },
  }), /issue scope/);
  await assert.rejects(() => issueProofV2({
    challengeStore: store,
    scope: { ...scope, ref: "refs/heads/feature" },
  }), /issue scope/);
  await assert.rejects(() => issueProofV2({
    challengeStore: store,
    scope: { ...scope, environment: "staging" },
  }), /issue scope/);
  const issued = await issueProofV2({ challengeStore: store, scope });
  assert.equal(issued.challenge.event_name, "workflow_dispatch");
  assert.equal(issued.challenge.ref, "refs/heads/main");
  assert.equal(issued.challenge.environment, "production");
});
