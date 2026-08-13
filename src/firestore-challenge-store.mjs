import { Firestore } from "@google-cloud/firestore";

import { issueKeyProofChallenge } from "./key-proof.mjs";

const CHALLENGE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const COLLECTION = "keyProofChallenges";

function valid(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function validStoredChallenge(value, challengeId) {
  if (!value || value.challenge_id !== challengeId || !["ISSUED", "CONSUMED"].includes(value.status)) {
    throw new Error("stored challenge is invalid");
  }
  if (!Number.isFinite(Date.parse(value.issued_at)) || !Number.isFinite(Date.parse(value.expires_at))) {
    throw new Error("stored challenge timestamps are invalid");
  }
  return value;
}

export class FirestoreChallengeStore {
  constructor({ firestore, collectionName = COLLECTION, now = () => new Date() } = {}) {
    this.firestore = firestore ?? new Firestore();
    this.collection = this.firestore.collection(collectionName);
    this.now = now;
  }

  async issue(scope) {
    const challenge = issueKeyProofChallenge(scope, this.now());
    await this.collection.doc(challenge.challenge_id).create(challenge);
    return challenge;
  }

  async get(challengeId) {
    valid(challengeId, CHALLENGE_ID, "challenge_id");
    const snapshot = await this.collection.doc(challengeId).get();
    if (!snapshot.exists) return null;
    return validStoredChallenge(snapshot.data(), challengeId);
  }

  async consume({ challenge_id: challengeId, expected_status: expectedStatus, consumed_status: consumedStatus, proof_digest: proofDigest }) {
    valid(challengeId, CHALLENGE_ID, "challenge_id");
    valid(proofDigest, SHA256, "proof_digest");
    if (expectedStatus !== "ISSUED" || consumedStatus !== "CONSUMED") {
      throw new Error("unsupported challenge transition");
    }
    const reference = this.collection.doc(challengeId);
    return this.firestore.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(reference);
      if (!snapshot.exists) return false;
      const challenge = validStoredChallenge(snapshot.data(), challengeId);
      const now = this.now();
      if (challenge.status !== "ISSUED" || now.getTime() >= Date.parse(challenge.expires_at)) return false;
      transaction.update(reference, {
        status: "CONSUMED",
        proof_digest: proofDigest,
        consumed_at: now.toISOString(),
      });
      return true;
    });
  }
}
