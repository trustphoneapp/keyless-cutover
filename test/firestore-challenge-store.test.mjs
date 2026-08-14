import assert from "node:assert/strict";
import test from "node:test";

import { FirestoreChallengeStore } from "../src/firestore-challenge-store.mjs";

class MemoryFirestore {
  documents = new Map();
  transactionTail = Promise.resolve();
  documentGets = 0;
  creates = 0;
  transactions = 0;
  updates = 0;
  updateTime = new Date("2026-08-13T12:01:01Z");
  readTime = new Date("2026-08-13T12:01:02Z");
  omitUpdateTime = false;
  omitReadTime = false;

  collection() {
    return {
      doc: (id) => ({
        id,
        create: async (value) => {
          this.creates += 1;
          if (this.documents.has(id)) throw new Error("already exists");
          this.documents.set(id, structuredClone(value));
        },
        get: async () => {
          this.documentGets += 1;
          return this.snapshot(id);
        },
      }),
    };
  }

  snapshot(id) {
    const value = this.documents.get(id);
    const snapshot = {
      exists: value !== undefined,
      data: () => structuredClone(value),
      updateTime: { toDate: () => new Date(this.updateTime) },
      readTime: new Date(this.readTime),
    };
    if (this.omitUpdateTime) delete snapshot.updateTime;
    if (this.omitReadTime) delete snapshot.readTime;
    return snapshot;
  }

  async runTransaction(callback) {
    this.transactions += 1;
    let release;
    const previous = this.transactionTail;
    this.transactionTail = new Promise((resolve) => { release = resolve; });
    await previous;
    const updates = [];
    try {
      const result = await callback({
        get: async (reference) => this.snapshot(reference.id),
        update: (reference, patch) => {
          this.updates += 1;
          updates.push([reference.id, patch]);
        },
      });
      for (const [id, patch] of updates) this.documents.set(id, { ...this.documents.get(id), ...patch });
      return result;
    } finally {
      release();
    }
  }
}

const scope = {
  migration_id: "migration-001",
  owner_id: "987654321",
  repository_id: "123456789",
  workflow_path: ".github/workflows/k0-deploy.yml",
  event_name: "push",
  ref: "refs/heads/main",
  environment: "production",
  client_email: "keyless-demo@example-project.iam.gserviceaccount.com",
};

const consumedChallenge = {
  status: "CONSUMED",
  migration_id: scope.migration_id,
  challenge_id: "12345678-1234-4123-8123-123456789abc",
  nonce: "n".repeat(43),
  issued_at: "2026-08-13T12:00:00.000Z",
  expires_at: "2026-08-13T12:05:00.000Z",
  owner_id: scope.owner_id,
  repository_id: scope.repository_id,
  workflow_path: scope.workflow_path,
  event_name: scope.event_name,
  ref: scope.ref,
  environment: scope.environment,
  client_email: scope.client_email,
  proof_digest: "a".repeat(64),
  consumed_at: "2026-08-13T12:01:00.000Z",
};

test("Firestore challenge store issues once and atomically consumes once", async () => {
  const firestore = new MemoryFirestore();
  const store = new FirestoreChallengeStore({
    firestore,
    now: () => new Date("2026-08-13T12:00:00Z"),
  });
  const challenge = await store.issue(scope);
  assert.equal((await store.get(challenge.challenge_id)).status, "ISSUED");

  const transition = {
    challenge_id: challenge.challenge_id,
    expected_status: "ISSUED",
    consumed_status: "CONSUMED",
    proof_digest: "b".repeat(64),
  };
  const results = await Promise.all([store.consume(transition), store.consume(transition)]);
  assert.deepEqual(results.sort(), [false, true]);
  const consumed = await store.get(challenge.challenge_id);
  assert.equal(consumed.status, "CONSUMED");
  assert.equal(consumed.proof_digest, transition.proof_digest);
});

test("Firestore challenge store rejects expired and malformed transitions", async () => {
  let now = new Date("2026-08-13T12:00:00Z");
  const store = new FirestoreChallengeStore({ firestore: new MemoryFirestore(), now: () => now });
  const challenge = await store.issue(scope);
  now = new Date("2026-08-13T12:05:00Z");
  assert.equal(await store.consume({
    challenge_id: challenge.challenge_id,
    expected_status: "ISSUED",
    consumed_status: "CONSUMED",
    proof_digest: "c".repeat(64),
  }), false);
  await assert.rejects(store.consume({
    challenge_id: challenge.challenge_id,
    expected_status: "ISSUED",
    consumed_status: "CONSUMED",
    proof_digest: "not-a-digest",
  }), /proof_digest/);
});

test("Firestore challenge store observes one exact consumed snapshot without writes", async () => {
  const firestore = new MemoryFirestore();
  firestore.documents.set(consumedChallenge.challenge_id, structuredClone(consumedChallenge));
  const store = new FirestoreChallengeStore({ firestore });
  assert.deepEqual(await store.observe(consumedChallenge.challenge_id), {
    ...consumedChallenge,
    update_time: "2026-08-13T12:01:01.000Z",
    read_time: "2026-08-13T12:01:02.000Z",
  });
  assert.equal(firestore.documentGets, 1);
  assert.equal(firestore.transactions, 0);
  assert.equal(firestore.creates, 0);
  assert.equal(firestore.updates, 0);
});

test("Firestore challenge observation rejects malformed state, metadata, scope, digest, and time", async () => {
  const cases = [
    { challenge: { ...consumedChallenge, status: "ISSUED" } },
    { challenge: { ...consumedChallenge, proof_digest: "wrong" } },
    { challenge: { ...consumedChallenge, owner_id: "not-numeric" } },
    { challenge: { ...consumedChallenge, unexpected: true } },
    { challenge: { ...consumedChallenge, consumed_at: "2026-08-13T12:05:00.000Z" } },
    { omitUpdateTime: true },
    { omitReadTime: true },
    { updateTime: new Date("2026-08-13T12:00:59Z") },
    { readTime: new Date("2026-08-13T12:01:00Z") },
  ];
  for (const testCase of cases) {
    const { challenge = consumedChallenge, ...metadata } = testCase;
    const firestore = new MemoryFirestore();
    firestore.documents.set(consumedChallenge.challenge_id, structuredClone(challenge));
    Object.assign(firestore, metadata);
    const store = new FirestoreChallengeStore({ firestore });
    await assert.rejects(() => store.observe(consumedChallenge.challenge_id));
    assert.equal(firestore.documentGets, 1);
    assert.equal(firestore.transactions, 0);
    assert.equal(firestore.updates, 0);
  }
});
