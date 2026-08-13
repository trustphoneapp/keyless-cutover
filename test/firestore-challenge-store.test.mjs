import assert from "node:assert/strict";
import test from "node:test";

import { FirestoreChallengeStore } from "../src/firestore-challenge-store.mjs";

class MemoryFirestore {
  documents = new Map();
  transactionTail = Promise.resolve();

  collection() {
    return {
      doc: (id) => ({
        id,
        create: async (value) => {
          if (this.documents.has(id)) throw new Error("already exists");
          this.documents.set(id, structuredClone(value));
        },
        get: async () => this.snapshot(id),
      }),
    };
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

const scope = {
  migration_id: "migration-001",
  owner_id: "987654321",
  repository_id: "123456789",
  workflow_path: ".github/workflows/k0-deploy.yml",
  event_name: "push",
  ref: "refs/heads/main",
  environment: "production",
  client_email: "keyless-demo@example-project.iam.gserviceaccount.com",
  private_key_id: "a".repeat(40),
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
