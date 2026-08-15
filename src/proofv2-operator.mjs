import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";

import { canonicalJson, decodeUtf8 } from "./evidence-artifact.mjs";
import {
  boundedGitHubPage,
  downloadGitHubBytesObserved,
  extractSingleJsonArtifact,
  fetchGitHubJson,
} from "./github-denial-evidence.mjs";
import { fetchGitHubProofObservation } from "./github-proof-observer.mjs";
import { requireGitHubReadToken } from "./github-token.mjs";
import { keyProofDigest, verifyGoogleKeyProofAuthority } from "./key-proof.mjs";
import { isRfc3339, timestampAtOrBefore, timestampBefore } from "./rfc3339.mjs";
import { rejectDuplicateJsonKeys } from "./observation-time.mjs";

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}$/;
const RUN_ID = /^\d+$/;
const CHALLENGE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA1 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const WORKFLOW = /^\.github\/workflows\/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,62}\/)*[A-Za-z0-9][A-Za-z0-9._-]{0,62}\.ya?ml$/;
const SERVICE_ACCOUNT = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;
const OPERATOR_RECEIPT_FIELDS = new Set([
  "version", "verified", "consumed", "replay_rejected", "replay_evidence", "recovered_after_consume",
  "migration_id", "challenge_id", "proof_digest", "key_id", "owner_id", "repository_id",
  "workflow_path", "event_name", "ref", "environment", "client_email", "run_id", "run_attempt",
  "head_sha", "run_started_at", "issued_at", "expires_at", "consumed_at",
]);
const OBSERVED_CHALLENGE_FIELDS = new Set([
  "status", "migration_id", "challenge_id", "nonce", "issued_at", "expires_at",
  "owner_id", "repository_id", "workflow_path", "event_name", "ref", "environment",
  "client_email", "proof_digest", "consumed_at", "update_time", "read_time",
]);
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const PROOF_FIELDS = new Set([
  "version", "algorithm", "migration_id", "challenge_id", "nonce", "issued_at", "expires_at",
  "owner_id", "repository_id", "workflow_path", "workflow_ref", "workflow_blob_sha", "head_sha",
  "run_id", "run_attempt", "actor_id", "triggering_actor", "event_name", "ref", "environment",
  "runner_environment", "client_email", "private_key_id", "message_sha256", "signature",
]);

function exact(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function exactProofShape(proof) {
  if (!proof || typeof proof !== "object" || Array.isArray(proof)) throw new Error("ProofV2 artifact is invalid");
  const keys = Object.keys(proof);
  if (keys.length !== PROOF_FIELDS.size || keys.some((key) => !PROOF_FIELDS.has(key))) {
    throw new Error("ProofV2 artifact fields are invalid");
  }
  return proof;
}

function exactObject(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === fields.size
    && Object.keys(value).every((key) => fields.has(key));
}

function bounded(value, pattern) {
  return typeof value === "string" && value.length > 0 && value.length <= 512
    && !/[\r\n]/.test(value) && (!pattern || pattern.test(value));
}

function validateOperatorReceipt(receipt) {
  if (!exactObject(receipt, OPERATOR_RECEIPT_FIELDS) || receipt.version !== 2
      || receipt.verified !== true || receipt.consumed !== true || receipt.replay_rejected !== true
      || receipt.replay_evidence !== "ORIGINAL_OPERATOR_ATOMIC_REPLAY_ATTEMPT"
      || typeof receipt.recovered_after_consume !== "boolean"
      || !bounded(receipt.migration_id) || !bounded(receipt.challenge_id, CHALLENGE_ID)
      || !bounded(receipt.proof_digest, SHA256) || !bounded(receipt.key_id, SHA1)
      || !bounded(receipt.owner_id, RUN_ID) || !bounded(receipt.repository_id, RUN_ID)
      || !bounded(receipt.workflow_path, WORKFLOW) || receipt.event_name !== "workflow_dispatch"
      || receipt.ref !== "refs/heads/main" || receipt.environment !== "production"
      || !bounded(receipt.client_email, SERVICE_ACCOUNT)
      || !bounded(receipt.run_id, RUN_ID) || !bounded(receipt.run_attempt, RUN_ID)
      || !bounded(receipt.head_sha, SHA1) || !isRfc3339(receipt.run_started_at)
      || !isRfc3339(receipt.issued_at) || !isRfc3339(receipt.expires_at)
      || !isRfc3339(receipt.consumed_at)
      || !timestampAtOrBefore(receipt.issued_at, receipt.run_started_at)
      || !timestampAtOrBefore(receipt.run_started_at, receipt.consumed_at)
      || !timestampBefore(receipt.consumed_at, receipt.expires_at)) {
    throw new Error("ProofV2 operator receipt is invalid");
  }
  return receipt;
}

function parseOperatorReceipt(receiptBytes) {
  if (!Buffer.isBuffer(receiptBytes) || !receiptBytes.length || receiptBytes.length > 64 * 1024) {
    throw new Error("ProofV2 operator receipt bytes are invalid");
  }
  let receipt;
  try {
    const text = decodeUtf8(receiptBytes);
    rejectDuplicateJsonKeys(text);
    receipt = JSON.parse(text);
  } catch (error) {
    if (error?.message === "duplicate JSON key") {
      throw new Error("ProofV2 operator receipt contains duplicate JSON keys");
    }
    throw new Error("ProofV2 operator receipt bytes are invalid");
  }
  if (!receiptBytes.equals(Buffer.from(canonicalJson(receipt), "utf8"))) {
    throw new Error("ProofV2 operator receipt bytes are not canonical");
  }
  return validateOperatorReceipt(receipt);
}

function snapshotObservedChallengeState(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || utilTypes.isProxy(value)) {
    throw new Error("ProofV2 observed challenge projection is invalid");
  }
  let prototype;
  let descriptors;
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    throw new Error("ProofV2 observed challenge projection is invalid");
  }
  if (prototype !== Object.prototype) throw new Error("ProofV2 observed challenge projection is invalid");
  const fields = Reflect.ownKeys(descriptors);
  if (fields.length !== OBSERVED_CHALLENGE_FIELDS.size
      || fields.some((field) => typeof field !== "string" || !OBSERVED_CHALLENGE_FIELDS.has(field))
      || fields.some((field) => !("value" in descriptors[field]) || descriptors[field].enumerable !== true
        || typeof descriptors[field].value !== "string")) {
    throw new Error("ProofV2 observed challenge projection is invalid");
  }
  const state = Object.freeze(Object.fromEntries(fields.map((field) => [field, descriptors[field].value])));
  if (state.status !== "CONSUMED" || !bounded(state.migration_id)
      || !bounded(state.challenge_id, CHALLENGE_ID) || !bounded(state.nonce, NONCE)
      || !bounded(state.owner_id, RUN_ID) || !bounded(state.repository_id, RUN_ID)
      || !bounded(state.workflow_path, WORKFLOW) || state.event_name !== "workflow_dispatch"
      || state.ref !== "refs/heads/main" || state.environment !== "production"
      || !bounded(state.client_email, SERVICE_ACCOUNT) || !bounded(state.proof_digest, SHA256)
      || !isRfc3339(state.issued_at) || !isRfc3339(state.expires_at)
      || !isRfc3339(state.consumed_at) || !isRfc3339(state.update_time) || !isRfc3339(state.read_time)
      || !timestampBefore(state.issued_at, state.consumed_at)
      || !timestampBefore(state.consumed_at, state.expires_at)
      || !timestampAtOrBefore(state.consumed_at, state.update_time)
      || !timestampAtOrBefore(state.update_time, state.read_time)) {
    throw new Error("ProofV2 observed challenge projection is invalid");
  }
  return state;
}

export function proofV2DispatchInputs(challenge) {
  if (challenge?.status !== "ISSUED") throw new Error("challenge is not issued");
  return {
    migration_id: challenge.migration_id,
    challenge_id: challenge.challenge_id,
    nonce: challenge.nonce,
    issued_at: challenge.issued_at,
    expires_at: challenge.expires_at,
  };
}

function requireProofV2IssueScope(scope) {
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) {
    throw new Error("ProofV2 issue scope is invalid");
  }
  if (scope.event_name !== "workflow_dispatch"
      || scope.ref !== "refs/heads/main"
      || scope.environment !== "production"
      || !bounded(scope.migration_id)
      || !bounded(scope.owner_id, RUN_ID)
      || !bounded(scope.repository_id, RUN_ID)
      || !bounded(scope.workflow_path, WORKFLOW)
      || !bounded(scope.client_email, SERVICE_ACCOUNT)) {
    throw new Error("ProofV2 issue scope is invalid");
  }
  return scope;
}

export async function issueProofV2({ challengeStore, scope }) {
  if (typeof challengeStore?.issue !== "function") throw new Error("an authoritative challenge store is required");
  const challenge = await challengeStore.issue(requireProofV2IssueScope(scope));
  return { challenge, dispatch_inputs: proofV2DispatchInputs(challenge) };
}

export async function collectProofV2({
  owner,
  repository,
  runId,
  workflowPath,
  environment,
  token,
  fetchImpl = fetch,
}) {
  exact(owner, OWNER, "owner");
  exact(repository, REPOSITORY, "repository");
  exact(String(runId), RUN_ID, "run_id");
  requireGitHubReadToken(token);
  const observed = await fetchGitHubProofObservation({
    owner,
    repository,
    runId: String(runId),
    workflowPath,
    environment,
    token,
    fetchImpl,
  });
  const base = `https://api.github.com/repos/${owner}/${repository}`;
  const response = await fetchGitHubJson(`${base}/actions/runs/${runId}/artifacts?per_page=100`, token, fetchImpl);
  const expectedName = `keyless-proof-v2-${observed.run_id}-${observed.run_attempt}`;
  const artifacts = boundedGitHubPage(response, "artifacts")
    .filter((artifact) => artifact?.name === expectedName && !artifact.expired);
  if (artifacts.length !== 1 || !Number.isInteger(artifacts[0].id)) {
    throw new Error("ProofV2 artifact is missing or ambiguous");
  }
  const { bytes: zip } = await downloadGitHubBytesObserved(
    `${base}/actions/artifacts/${artifacts[0].id}/zip`,
    token,
    fetchImpl,
    512_000,
  );
  const proof = exactProofShape(extractSingleJsonArtifact(zip, "keyless-proof-v2.json"));
  if (proof.run_id !== observed.run_id || proof.run_attempt !== observed.run_attempt) {
    throw new Error("ProofV2 artifact does not match the observed run");
  }
  return { proof, observed, artifact_id: String(artifacts[0].id), artifact_name: expectedName };
}

export async function verifyAndConsumeProofV2({
  challengeStore,
  proof,
  observed,
  getGoogleKey,
  fetchImpl = fetch,
  now = new Date(),
}) {
  if (typeof challengeStore?.get !== "function" || typeof challengeStore?.consume !== "function") {
    throw new Error("an authoritative challenge store is required");
  }
  const digest = keyProofDigest(proof);
  let challenge = await challengeStore.get(proof?.challenge_id);
  if (!challenge) throw new Error("ProofV2 challenge is missing");
  let recoveredAfterConsume = challenge.status === "CONSUMED";
  if (recoveredAfterConsume && challenge.proof_digest !== digest) {
    throw new Error("ProofV2 consumed digest does not match");
  }
  const authorityNow = recoveredAfterConsume ? new Date(challenge.consumed_at) : new Date(now);
  if (!Number.isFinite(authorityNow.getTime())) throw new Error("ProofV2 consumed time is invalid");
  let verified;
  try {
    verified = await verifyGoogleKeyProofAuthority({
      proof,
      challenge,
      observed,
      getGoogleKey,
      fetchImpl,
      now: authorityNow,
    });
  } catch (cause) {
    throw new Error("ProofV2 verification or atomic consume failed", { cause });
  }
  if (!verified) throw new Error("ProofV2 verification or atomic consume failed");
  if (!recoveredAfterConsume) {
    const transitioned = await challengeStore.consume({
      challenge_id: proof.challenge_id,
      expected_status: "ISSUED",
      consumed_status: "CONSUMED",
      proof_digest: digest,
    });
    if (!transitioned) {
      challenge = await challengeStore.get(proof.challenge_id);
      if (challenge?.status !== "CONSUMED" || challenge.proof_digest !== digest) {
        throw new Error("ProofV2 verification or atomic consume failed");
      }
      recoveredAfterConsume = true;
    }
  }
  const consumed = await challengeStore.get(proof.challenge_id);
  if (consumed?.status !== "CONSUMED" || typeof consumed.proof_digest !== "string") {
    throw new Error("ProofV2 consumed state is invalid");
  }
  const replayAccepted = await challengeStore.consume({
    challenge_id: proof.challenge_id,
    expected_status: "ISSUED",
    consumed_status: "CONSUMED",
    proof_digest: consumed.proof_digest,
  });
  if (replayAccepted) throw new Error("ProofV2 replay was accepted");
  return validateOperatorReceipt({
    version: 2,
    verified: true,
    consumed: true,
    replay_rejected: true,
    replay_evidence: "ORIGINAL_OPERATOR_ATOMIC_REPLAY_ATTEMPT",
    recovered_after_consume: recoveredAfterConsume,
    migration_id: consumed.migration_id,
    challenge_id: proof.challenge_id,
    proof_digest: consumed.proof_digest,
    key_id: proof.private_key_id,
    owner_id: consumed.owner_id,
    repository_id: consumed.repository_id,
    workflow_path: consumed.workflow_path,
    event_name: consumed.event_name,
    ref: consumed.ref,
    environment: consumed.environment,
    client_email: consumed.client_email,
    run_id: proof.run_id,
    run_attempt: proof.run_attempt,
    head_sha: proof.head_sha,
    run_started_at: observed.started_at,
    issued_at: consumed.issued_at,
    expires_at: consumed.expires_at,
    consumed_at: consumed.consumed_at,
  });
}

export async function collectReadOnlyConsumedProofV2State({
  challengeStore,
  proof,
  observed,
  operatorReceiptBytes,
  getGoogleKey,
  fetchImpl = fetch,
}) {
  const receiptBytes = Buffer.isBuffer(operatorReceiptBytes) ? Buffer.from(operatorReceiptBytes) : null;
  let proofSnapshot;
  let observedSnapshot;
  try {
    proofSnapshot = structuredClone(proof);
    observedSnapshot = structuredClone(observed);
  } catch {
    throw new Error("ProofV2 recollection input is invalid");
  }
  const receipt = parseOperatorReceipt(receiptBytes);
  exactProofShape(proofSnapshot);
  if (typeof challengeStore?.observe !== "function" || typeof getGoogleKey !== "function") {
    throw new Error("read-only authoritative ProofV2 sources are required");
  }
  const proofDigest = keyProofDigest(proofSnapshot);
  const receiptBindings = {
    migration_id: proofSnapshot.migration_id,
    challenge_id: proofSnapshot.challenge_id,
    proof_digest: proofDigest,
    key_id: proofSnapshot.private_key_id,
    owner_id: proofSnapshot.owner_id,
    repository_id: proofSnapshot.repository_id,
    workflow_path: proofSnapshot.workflow_path,
    event_name: proofSnapshot.event_name,
    ref: proofSnapshot.ref,
    environment: proofSnapshot.environment,
    client_email: proofSnapshot.client_email,
    run_id: proofSnapshot.run_id,
    run_attempt: proofSnapshot.run_attempt,
    head_sha: proofSnapshot.head_sha,
    run_started_at: observedSnapshot?.started_at,
    issued_at: proofSnapshot.issued_at,
    expires_at: proofSnapshot.expires_at,
  };
  if (Object.entries(receiptBindings).some(([field, value]) => receipt[field] !== value)) {
    throw new Error("ProofV2 operator receipt does not match proof and run identity");
  }
  const observedState = await challengeStore.observe(proofSnapshot.challenge_id);
  const state = snapshotObservedChallengeState(observedState);
  const stateBindings = [
    "migration_id", "challenge_id", "proof_digest", "owner_id", "repository_id", "workflow_path",
    "event_name", "ref", "environment", "client_email", "issued_at", "expires_at", "consumed_at",
  ];
  if (state?.status !== "CONSUMED"
      || stateBindings.some((field) => state[field] !== receipt[field])
      || !isRfc3339(state.update_time) || !isRfc3339(state.read_time)) {
    throw new Error("ProofV2 consumed state does not match its operator receipt");
  }
  const verified = await verifyGoogleKeyProofAuthority({
    proof: proofSnapshot,
    challenge: state,
    observed: observedSnapshot,
    getGoogleKey,
    fetchImpl,
    now: new Date(state.consumed_at),
  });
  if (!verified) throw new Error("ProofV2 read-only authority verification failed");
  return {
    observedAt: state.read_time,
    challengeState: {
      version: 3,
      status: "CONSUMED",
      verified: true,
      consumed: true,
      replay_rejected: true,
      replay_evidence: "ORIGINAL_OPERATOR_RECEIPT_ONLY",
      migration_id: state.migration_id,
      challenge_id: state.challenge_id,
      proof_digest: state.proof_digest,
      key_id: proofSnapshot.private_key_id,
      owner_id: state.owner_id,
      repository_id: state.repository_id,
      workflow_path: state.workflow_path,
      event_name: state.event_name,
      ref: state.ref,
      environment: state.environment,
      client_email: state.client_email,
      run_id: proofSnapshot.run_id,
      run_attempt: proofSnapshot.run_attempt,
      head_sha: proofSnapshot.head_sha,
      run_started_at: observedSnapshot.started_at,
      issued_at: state.issued_at,
      expires_at: state.expires_at,
      consumed_at: state.consumed_at,
      update_time: state.update_time,
      receipt_sha256: createHash("sha256").update(receiptBytes).digest("hex"),
    },
  };
}
