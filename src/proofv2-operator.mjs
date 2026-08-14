import { createHash } from "node:crypto";

import {
  downloadGitHubBytes,
  extractSingleJsonArtifact,
  fetchGitHubJson,
} from "./github-denial-evidence.mjs";
import { fetchGitHubProofObservation } from "./github-proof-observer.mjs";
import { requireGitHubReadToken } from "./github-token.mjs";
import { keyProofDigest, verifyGoogleKeyProofAuthority } from "./key-proof.mjs";

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}$/;
const RUN_ID = /^\d+$/;
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

export async function issueProofV2({ challengeStore, scope }) {
  if (typeof challengeStore?.issue !== "function") throw new Error("an authoritative challenge store is required");
  const challenge = await challengeStore.issue(scope);
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
  const artifacts = response?.artifacts?.filter((artifact) => artifact?.name === expectedName && !artifact.expired);
  if (!Array.isArray(artifacts) || artifacts.length !== 1 || !Number.isInteger(artifacts[0].id)) {
    throw new Error("ProofV2 artifact is missing or ambiguous");
  }
  const zip = await downloadGitHubBytes(
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
  return {
    version: 1,
    verified: true,
    consumed: true,
    replay_rejected: true,
    recovered_after_consume: recoveredAfterConsume,
    challenge_id: proof.challenge_id,
    proof_digest: consumed.proof_digest,
    key_id: proof.private_key_id,
    run_id: proof.run_id,
    observed_at: new Date(now).toISOString(),
    receipt_sha256: createHash("sha256").update(JSON.stringify({
      challenge_id: proof.challenge_id,
      proof_digest: consumed.proof_digest,
      key_id: proof.private_key_id,
      run_id: proof.run_id,
    })).digest("hex"),
  };
}
