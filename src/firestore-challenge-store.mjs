import { Firestore } from "@google-cloud/firestore";

import { issueKeyProofChallenge } from "./key-proof.mjs";
import { isRfc3339, timestampAtOrBefore, timestampBefore, timestampNanoseconds, formatTimestampNanoseconds } from "./rfc3339.mjs";

const CHALLENGE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const NUMERIC = /^\d+$/;
const WORKFLOW = /^\.github\/workflows\/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,62}\/)*[A-Za-z0-9][A-Za-z0-9._-]{0,62}\.ya?ml$/;
const REF = /^refs\/[A-Za-z0-9._/-]+$/;
const EVENT_NAME = /^(?:workflow_dispatch|push)$/;
const ENVIRONMENT = /^production$/;
const SERVICE_ACCOUNT = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const COLLECTION = "keyProofChallenges";
const ISSUED_FIELDS = new Set([
  "status", "migration_id", "challenge_id", "nonce", "issued_at", "expires_at",
  "owner_id", "repository_id", "workflow_path", "event_name", "ref", "environment",
  "client_email",
]);
const CONSUMED_FIELDS = new Set([
  "status", "migration_id", "challenge_id", "nonce", "issued_at", "expires_at",
  "owner_id", "repository_id", "workflow_path", "event_name", "ref", "environment",
  "client_email", "proof_digest", "consumed_at",
]);

function valid(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function exactChallengeObject(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === fields.size
    && Object.keys(value).every((field) => fields.has(field));
}

function validIssuedChallenge(value, challengeId) {
  if (!exactChallengeObject(value, ISSUED_FIELDS)
      || value.status !== "ISSUED" || value.challenge_id !== challengeId
      || !bounded(value.migration_id) || !bounded(value.nonce, NONCE)
      || !bounded(value.owner_id, NUMERIC) || !bounded(value.repository_id, NUMERIC)
      || !bounded(value.workflow_path, WORKFLOW) || !bounded(value.event_name, EVENT_NAME)
      || !bounded(value.ref, REF) || !bounded(value.environment, ENVIRONMENT)
      || !bounded(value.client_email, SERVICE_ACCOUNT)
      || !isRfc3339(value.issued_at) || !isRfc3339(value.expires_at)
      || !timestampBefore(value.issued_at, value.expires_at)) {
    throw new Error("stored challenge is invalid");
  }
  return value;
}

function validStoredChallenge(value, challengeId) {
  if (value?.status === "ISSUED") return validIssuedChallenge(value, challengeId);
  if (value?.status === "CONSUMED") {
    if (!exactChallengeObject(value, CONSUMED_FIELDS)
        || value.challenge_id !== challengeId
        || !bounded(value.migration_id) || !bounded(value.nonce, NONCE)
        || !bounded(value.owner_id, NUMERIC) || !bounded(value.repository_id, NUMERIC)
        || !bounded(value.workflow_path, WORKFLOW) || !bounded(value.event_name, EVENT_NAME)
        || !bounded(value.ref, REF) || !bounded(value.environment, ENVIRONMENT)
        || !bounded(value.client_email, SERVICE_ACCOUNT) || !bounded(value.proof_digest, SHA256)
        || !isRfc3339(value.issued_at) || !isRfc3339(value.expires_at) || !isRfc3339(value.consumed_at)
        || !timestampBefore(value.issued_at, value.consumed_at)
        || !timestampBefore(value.consumed_at, value.expires_at)) {
      throw new Error("stored challenge is invalid");
    }
    return value;
  }
  throw new Error("stored challenge is invalid");
}

function bounded(value, pattern) {
  return typeof value === "string" && value.length > 0 && value.length <= 512
    && !/[\r\n]/.test(value) && (!pattern || pattern.test(value));
}

function snapshotTime(value, name) {
  let date;
  try {
    date = value instanceof Date ? value : value?.toDate?.();
  } catch {
    throw new Error(`challenge snapshot ${name} is invalid`);
  }
  if (!(date instanceof Date) || !Number.isFinite(date.getTime())) {
    throw new Error(`challenge snapshot ${name} is invalid`);
  }
  return new Date(date.getTime()).toISOString();
}

function observedConsumedChallenge(value, challengeId, updateTime, readTime) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).length !== CONSUMED_FIELDS.size
      || Object.keys(value).some((field) => !CONSUMED_FIELDS.has(field))
      || value.status !== "CONSUMED" || value.challenge_id !== challengeId
      || !bounded(value.migration_id) || !bounded(value.nonce, NONCE)
      || !bounded(value.owner_id, NUMERIC) || !bounded(value.repository_id, NUMERIC)
      || !bounded(value.workflow_path, WORKFLOW) || !bounded(value.event_name, EVENT_NAME)
      || !bounded(value.ref, REF) || !bounded(value.environment, ENVIRONMENT)
      || !bounded(value.client_email, SERVICE_ACCOUNT) || !bounded(value.proof_digest, SHA256)
      || !isRfc3339(value.issued_at) || !isRfc3339(value.expires_at) || !isRfc3339(value.consumed_at)
      || !timestampBefore(value.issued_at, value.consumed_at)
      || !timestampBefore(value.consumed_at, value.expires_at)
      || !timestampAtOrBefore(value.consumed_at, updateTime)
      || !timestampAtOrBefore(updateTime, readTime)) {
    throw new Error("observed consumed challenge is invalid");
  }
  return {
    status: "CONSUMED",
    migration_id: value.migration_id,
    challenge_id: value.challenge_id,
    nonce: value.nonce,
    issued_at: value.issued_at,
    expires_at: value.expires_at,
    owner_id: value.owner_id,
    repository_id: value.repository_id,
    workflow_path: value.workflow_path,
    event_name: value.event_name,
    ref: value.ref,
    environment: value.environment,
    client_email: value.client_email,
    proof_digest: value.proof_digest,
    consumed_at: value.consumed_at,
    update_time: updateTime,
    read_time: readTime,
  };
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

  async observe(challengeId) {
    valid(challengeId, CHALLENGE_ID, "challenge_id");
    const snapshot = await this.collection.doc(challengeId).get();
    if (!snapshot.exists) throw new Error("consumed challenge is missing");
    const updateTime = snapshotTime(snapshot.updateTime, "update time");
    const readTime = snapshotTime(snapshot.readTime, "read time");
    return observedConsumedChallenge(snapshot.data(), challengeId, updateTime, readTime);
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
      if (challenge.status !== "ISSUED") return false;
      const nowAt = this.now().toISOString();
      let consumedAt = nowAt;
      if (!timestampBefore(challenge.issued_at, consumedAt)) {
        const issuedNs = timestampNanoseconds(challenge.issued_at);
        if (issuedNs === null) return false;
        consumedAt = formatTimestampNanoseconds(issuedNs + 1n);
        if (consumedAt === null || !isRfc3339(consumedAt) || !timestampBefore(challenge.issued_at, consumedAt)) {
          return false;
        }
      }
      if (!timestampBefore(consumedAt, challenge.expires_at)) return false;
      transaction.update(reference, {
        status: "CONSUMED",
        proof_digest: proofDigest,
        consumed_at: consumedAt,
      });
      return true;
    });
  }
}
