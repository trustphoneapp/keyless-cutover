import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

import { verifyK0EvidenceSemantics } from "../src/k0-evidence-semantics.mjs";
import { verifyK0Manifest } from "../src/k0-manifest.mjs";

const MAX_DOCUMENT_BYTES = 1_000_000;
const CREDENTIAL = /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"private_key"\s*:|ya29\.[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35})/;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

function bounded(value, maximum = 500) {
  return typeof value === "string" && value.length > 0 && value.length <= maximum && !/[\r\n]/.test(value);
}

async function readBoundedJson(path) {
  const bytes = await readFile(resolve(path));
  if (bytes.length > MAX_DOCUMENT_BYTES) throw new Error("status input is too large");
  const text = bytes.toString("utf8");
  if (CREDENTIAL.test(text)) throw new Error("status input contains credential-shaped material");
  return { bytes, value: JSON.parse(text) };
}

function gate(label, state, detail) {
  return { label, state, detail };
}

function failedStatus(code = "CHECKPOINT_REJECTED") {
  return {
    version: 1,
    status: "NO_GO_VERIFICATION_FAILED",
    release_ready: false,
    cutover_verified: false,
    eyebrow: "Evidence verification stopped",
    headline: "No proof, no green light.",
    summary: "The configured evidence could not be verified. Keyless failed closed and published no security outcome.",
    recorded_at: null,
    checkpoint_sha256: null,
    metrics: [],
    gates: [gate("Evidence verifier", "failed", code)],
    blockers: ["Replace the rejected input with a credential-free, verifier-compatible evidence bundle."],
    sources: [],
    limitations: ["A rejected or missing evidence document cannot be relabeled as success."],
  };
}

function checkpointStatus(bytes, checkpoint) {
  if (checkpoint?.version !== 1 || checkpoint?.status !== "NO_GO_INCOMPLETE") throw new Error("checkpoint status is not fail-closed");
  if (!bounded(checkpoint.recorded_at) || !Number.isFinite(Date.parse(checkpoint.recorded_at))) throw new Error("checkpoint timestamp is invalid");
  if (!REPOSITORY.test(checkpoint.repository?.full_name ?? "")) throw new Error("checkpoint repository is invalid");
  if (!Number.isInteger(checkpoint.repository?.cutover_pr) || checkpoint.repository.cutover_pr < 1
      || !bounded(checkpoint.gcp?.legacy_revision)
      || !String(checkpoint.h2_wrong_repository?.github_run_url ?? "").startsWith("https://github.com/")) {
    throw new Error("checkpoint public identifiers are invalid");
  }
  if (!Array.isArray(checkpoint.blockers) || checkpoint.blockers.length < 1 || checkpoint.blockers.length > 20
      || !checkpoint.blockers.every((item) => bounded(item))) throw new Error("checkpoint blockers are invalid");
  if (checkpoint.wif_readback?.downstream_permission_added !== false
      || checkpoint.proof_v2?.firestore_consumed_once !== true
      || checkpoint.proof_v2?.replay_rejected !== true
      || checkpoint.proof_v2?.authoritative_status !== "HOLD_INDEPENDENT_REVIEW_MISSING"
      || checkpoint.h2_wrong_repository?.forbidden_revision_unchanged !== true
      || checkpoint.agent_eval?.pass !== true) throw new Error("checkpoint readiness facts are invalid");
  if (![checkpoint.agent_eval.supported, checkpoint.agent_eval.refusal, checkpoint.agent_eval.recovery, checkpoint.agent_eval.schema_valid].every((value) => bounded(value, 20))
      || !Number.isInteger(checkpoint.agent_eval.paired_gain) || checkpoint.agent_eval.paired_gain < 0
      || !Number.isInteger(checkpoint.agent_eval.forbidden) || checkpoint.agent_eval.forbidden !== 0) {
    throw new Error("checkpoint evaluation facts are invalid");
  }

  const [owner, repo] = checkpoint.repository.full_name.split("/");
  return {
    version: 1,
    status: "NO_GO_INCOMPLETE",
    release_ready: false,
    cutover_verified: false,
    eyebrow: "Live K0 checkpoint",
    headline: "Remove the key. Prove what still works.",
    summary: "The substrate and bounded agent are live, but Keyless will not claim a completed cutover until every human and hostile-path receipt is independently reconstructable.",
    recorded_at: new Date(checkpoint.recorded_at).toISOString(),
    checkpoint_sha256: createHash("sha256").update(bytes).digest("hex"),
    metrics: [
      { value: checkpoint.agent_eval.supported, label: "supported cases" },
      { value: checkpoint.agent_eval.refusal, label: "safe refusals" },
      { value: checkpoint.agent_eval.recovery, label: "recoveries" },
      { value: checkpoint.agent_eval.schema_valid, label: "schema-valid calls" },
    ],
    gates: [
      gate("Legacy baseline", "observed", checkpoint.gcp.legacy_revision),
      gate("WIF trust read-back", "observed", "No downstream permission added"),
      gate("ProofV2 replay", "hold", "Consumed once; independent review missing"),
      gate("Gemini necessity", "passed", "Sealed release evaluation passed"),
      gate("H1 foreign owner", "missing", "Not run"),
      gate("H2 wrong repository", "denied", `GitHub run ${checkpoint.h2_wrong_repository.github_run_id}`),
      gate("H3–H8 controls", "missing", "Protected cutover required"),
      gate("Disable + WIF continuity", "missing", "Human action required"),
    ],
    blockers: [...checkpoint.blockers],
    sources: [
      { label: "Cumulative release PR", href: `https://github.com/${owner}/${repo}/pull/11` },
      { label: "Compiler-produced cutover PR", href: `https://github.com/${owner}/${repo}/pull/${checkpoint.repository.cutover_pr}` },
      { label: "Live H2 denial run", href: checkpoint.h2_wrong_repository.github_run_url },
    ],
    limitations: [
      "ProofV2 is readiness evidence until an independent protected-environment review exists.",
      "The legacy key remains enabled; no completed cutover is claimed.",
      "A model output never decides authorization, denial, or receipt completeness.",
    ],
  };
}

async function manifestStatus(manifestPath, bytes, manifest) {
  const structural = verifyK0Manifest(manifest);
  if (!structural.ok) throw new Error("manifest structure was rejected");
  const semantic = await verifyK0EvidenceSemantics(
    manifest,
    (id) => readFile(join(dirname(resolve(manifestPath)), "artifacts", `${id}.json`)),
  );
  if (!semantic.ok) throw new Error("manifest evidence was rejected");
  const sources = manifest.evidence
    .filter((item) => typeof item.public_url === "string" && item.public_url.startsWith("https://"))
    .slice(0, 8)
    .map((item) => ({ label: `${item.id} · ${item.kind}`, href: item.public_url }));
  return {
    version: 1,
    status: "K0_VERIFIED_RECEIPT_PENDING",
    release_ready: false,
    cutover_verified: true,
    eyebrow: "K0 evidence verified",
    headline: "The cutover is proven. The receipt is not signed yet.",
    summary: "Every K0 manifest and evidence-artifact invariant passed, but final release remains blocked until an asymmetric KMS signature and independent verification exist.",
    recorded_at: manifest.evidence.map((item) => item.observed_at).sort().at(-1),
    checkpoint_sha256: createHash("sha256").update(bytes).digest("hex"),
    metrics: [
      { value: "8/8", label: "hostile paths denied" },
      { value: "2/2", label: "WIF deployments" },
      { value: "1/1", label: "legacy auth rejected" },
      { value: String(manifest.evidence.length), label: "evidence artifacts" },
    ],
    gates: [
      gate("Exact old key", "passed", "ProofV2 verified and consumed"),
      gate("WIF permission parity", "passed", "No downstream permission added"),
      gate("Authorized deployment", "passed", manifest.revisions.wif_1),
      gate("H1–H8 controls", "passed", "All reached intended controls"),
      gate("Human key disable", "passed", "Live key state and audit entry agree"),
      gate("Fresh legacy rejection", "passed", "New hosted request denied"),
      gate("Post-disable WIF", "passed", manifest.revisions.wif_2),
      gate("KMS receipt", "missing", "Signature and public verification pending"),
    ],
    blockers: ["Create and independently verify the scoped asymmetric KMS receipt."],
    sources,
    limitations: [...manifest.limitations],
  };
}

export async function loadConsoleStatus({ checkpointPath, manifestPath } = {}) {
  try {
    if (manifestPath) {
      const { bytes, value } = await readBoundedJson(manifestPath);
      return await manifestStatus(manifestPath, bytes, value);
    }
    if (!checkpointPath) throw new Error("checkpoint path is required");
    const { bytes, value } = await readBoundedJson(checkpointPath);
    return checkpointStatus(bytes, value);
  } catch {
    return failedStatus();
  }
}
