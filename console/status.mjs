import { createHash } from "node:crypto";
import { resolve } from "node:path";

import { readBoundedFile, readK0BundleDirectory } from "../src/k0-bundle-files.mjs";
import { verifyKmsSignature } from "../src/k0-kms.mjs";
import { createK0Receipt, verifyK0Receipt } from "../src/k0-receipt.mjs";

const MAX_DOCUMENT_BYTES = 1_000_000;
const MAX_SIDECAR_BYTES = 16_384;
const CREDENTIAL = /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"private_key"\s*:|ya29\.[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35})/;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SHA256 = /^[a-f0-9]{64}$/;
const KEY_ID = /^[a-f0-9]{40}$/;
const NUMERIC = /^\d+$/;
const HOSTILE_IDS = ["H1", "H2", "H3", "H4", "H5", "H6", "H7", "H8"];
const CONSOLE_STATUS_SNAPSHOTS = new WeakMap();

function recordConsoleStatus(status) {
  const snapshot = structuredClone(status);
  CONSOLE_STATUS_SNAPSHOTS.set(status, {
    snapshot,
    fingerprint: createHash("sha256").update(JSON.stringify(snapshot)).digest("hex"),
  });
  return status;
}

export function getUntamperedConsoleStatusSnapshot(status) {
  try {
    if (status === null || typeof status !== "object" || !CONSOLE_STATUS_SNAPSHOTS.has(status)) {
      throw new Error("console status provenance is invalid");
    }
    const recorded = CONSOLE_STATUS_SNAPSHOTS.get(status);
    const fingerprint = createHash("sha256").update(JSON.stringify(status)).digest("hex");
    if (fingerprint !== recorded.fingerprint) throw new Error("console status was mutated");
    return structuredClone(recorded.snapshot);
  } catch {
    throw new Error("console status provenance is invalid");
  }
}

function bounded(value, maximum = 500) {
  return typeof value === "string" && value.length > 0 && value.length <= maximum && !/[\r\n]/.test(value);
}

async function readBoundedJson(path) {
  const bytes = await readBoundedFile(resolve(path), MAX_DOCUMENT_BYTES);
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
    authorization: "VERIFICATION_FAILED",
    release_ready: false,
    cutover_verified: false,
    signature_verified: false,
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
      || !bounded(checkpoint.gcp?.wif_1_revision)
      || !String(checkpoint.pre_disable?.wif_1_github_run_url ?? "").startsWith("https://github.com/")) {
    throw new Error("checkpoint public identifiers are invalid");
  }
  if (!Array.isArray(checkpoint.blockers) || checkpoint.blockers.length < 1 || checkpoint.blockers.length > 20
      || !checkpoint.blockers.every((item) => bounded(item))) throw new Error("checkpoint blockers are invalid");
  const hostile = checkpoint.pre_disable?.hostile_tests;
  if (checkpoint.pre_disable?.status !== "K0_PREDISABLE_VERIFIED"
      || checkpoint.pre_disable?.hostile_controls_passed !== "8/8"
      || !bounded(checkpoint.pre_disable?.forbidden_revision_before)
      || checkpoint.pre_disable.forbidden_revision_before !== checkpoint.pre_disable.forbidden_revision_after
      || !Array.isArray(hostile) || hostile.length !== 8
      || hostile.some((item, index) => item?.id !== HOSTILE_IDS[index]
        || !/^\d+$/.test(item?.run_id ?? "")
        || item?.outcome !== "DENIED"
        || item?.reached_control !== true
        || !SHA256.test(item?.log_sha256 ?? ""))) {
    throw new Error("checkpoint pre-disable evidence is invalid");
  }
  if (checkpoint.wif_readback?.downstream_permission_added !== false
      || checkpoint.proof_v2?.firestore_consumed_once !== true
      || checkpoint.proof_v2?.replay_rejected !== true
      || checkpoint.proof_v2?.authoritative_status !== "VERIFIED_INDEPENDENT_REVIEW"
      || checkpoint.agent_eval?.pass !== true) throw new Error("checkpoint readiness facts are invalid");
  const keyDisable = checkpoint.key_disable;
  if (keyDisable?.status !== "KEY_DISABLED_OBSERVED"
      || keyDisable?.disabled !== true
      || !KEY_ID.test(keyDisable?.key_id ?? "")
      || !NUMERIC.test(keyDisable?.service_account_unique_id ?? "")
      || keyDisable?.audit_method !== "google.iam.admin.v1.DisableServiceAccountKey"
      || keyDisable?.audit_resource !== `projects/-/serviceAccounts/${keyDisable.service_account_unique_id}/keys/${keyDisable.key_id}`
      || !bounded(keyDisable?.human_actor)
      || !bounded(keyDisable?.audit_insert_id)
      || !bounded(keyDisable?.audit_timestamp)
      || !Number.isFinite(Date.parse(keyDisable.audit_timestamp))) {
    throw new Error("checkpoint key-disable evidence is invalid");
  }
  if (![checkpoint.agent_eval.supported, checkpoint.agent_eval.refusal, checkpoint.agent_eval.recovery, checkpoint.agent_eval.schema_valid].every((value) => bounded(value, 20))
      || !Number.isInteger(checkpoint.agent_eval.paired_gain) || checkpoint.agent_eval.paired_gain < 0
      || !Number.isInteger(checkpoint.agent_eval.forbidden) || checkpoint.agent_eval.forbidden !== 0) {
    throw new Error("checkpoint evaluation facts are invalid");
  }

  const [owner, repo] = checkpoint.repository.full_name.split("/");
  return {
    version: 1,
    status: "NO_GO_INCOMPLETE",
    authorization: "INCOMPLETE",
    release_ready: false,
    cutover_verified: false,
    signature_verified: false,
    eyebrow: "Pre-disable v3 checkpoint, sealed before key disable",
    headline: "Pre-disable half of v3 is complete. Continuity is blocked, not missing.",
    summary: "This key completed a fresh legacy baseline, ProofV2, the WIF cutover, and all 8 hostile denials, then had its canonical archive checkpoint reviewed and merged before a human disabled it. wif-2 continuity cannot be produced on this repository for a documented structural reason; the disabled key must not be re-enabled to attempt it.",
    recorded_at: new Date(checkpoint.recorded_at).toISOString(),
    checkpoint_sha256: createHash("sha256").update(bytes).digest("hex"),
    metrics: [
      { value: checkpoint.agent_eval.supported, label: "supported cases" },
      { value: checkpoint.agent_eval.refusal, label: "safe refusals" },
      { value: checkpoint.agent_eval.recovery, label: "recoveries" },
      { value: checkpoint.agent_eval.schema_valid, label: "schema-valid calls" },
    ],
    gates: [
      gate("Legacy baseline", "historical", checkpoint.gcp.legacy_revision),
      gate("WIF trust read-back", "historical", "No downstream permission added in the recorded run"),
      gate("ProofV2 replay", "historical", `Reviewed run ${checkpoint.proof_v2.github_run_id}; consumed once; replay rejected`),
      gate("Gemini necessity", "passed", "Sealed release evaluation passed"),
      gate("H1 foreign owner", "historical", `GitHub run ${hostile[0].run_id}`),
      gate("H2 wrong repository", "historical", `GitHub run ${hostile[1].run_id}`),
      gate("H3–H8 controls", "historical", "Six intended controls reached and denied"),
      gate("Human key disable", "historical", `Key ${keyDisable.key_id}; actor ${keyDisable.human_actor}`),
      gate("Canonical pre-disable archive checkpoint", "passed", "Reviewed and merged (PR #35) before key disable"),
      gate("Fresh disposable v3 transaction", "blocked", "Pre-disable half complete through key disable; wif-2 continuity permanently blocked by an audit-log collision on this repository"),
    ],
    blockers: [
      "WIF-2 continuity cannot be produced on this repository: H6 and H8's audit-log entries are indistinguishable from deploy's own exchange, so no query can isolate a clean two-entry evidence window.",
      "Gating the hostile jobs to fix that collision changes the workflow's bytes, which breaks the wif_1 blob-SHA pin that legacy_baseline validation requires.",
      "The disabled key must never be re-enabled to attempt continuity; this transaction's evidence stands as pre-disable v3 completion only.",
    ],
    sources: [
      { label: "Compiler-owned WIF cutover PR", href: `https://github.com/${owner}/${repo}/pull/${checkpoint.repository.cutover_pr}` },
      { label: "Canonical pre-disable archive checkpoint PR", href: `https://github.com/${owner}/${repo}/pull/35` },
      { label: "Reviewed ProofV2 run", href: `https://github.com/${owner}/${repo}/actions/runs/${checkpoint.proof_v2.github_run_id}` },
      { label: "WIF-1 cutover run (H6–H8 same batch)", href: checkpoint.pre_disable.wif_1_github_run_url },
      { label: "H1 foreign-owner denial run", href: "https://github.com/cherala2002/keyless-h1-probe/actions/runs/32765012489" },
    ],
    limitations: [
      "ProofV2 proves the reviewed exact-key handoff only; WIF cutover evidence is recorded separately.",
      "The legacy key is disabled, but previously issued access tokens are not claimed revoked.",
      "H1–H8 prove only the named identities and controls during their recorded runs.",
      "wif-2 continuity is structurally blocked on this repository, not merely incomplete, and cannot be produced without changing the workflow bytes pinned by wif_1 or reverting the cutover.",
      "A model output never decides authorization, denial, or receipt completeness.",
    ],
  };
}

function bundleStatus(bundle, receipt, signatureVerified) {
  const { manifest } = bundle;
  const sources = manifest.evidence
    .filter((item) => typeof item.public_url === "string" && item.public_url.startsWith("https://"))
    .slice(0, 8)
    .map((item) => ({ label: `${item.id} · ${item.kind}`, href: item.public_url }));
  return {
    version: 1,
    status: "K0_VERIFIED_RECEIPT_PENDING",
    authorization: "RECOLLECTION_REQUIRED",
    release_ready: false,
    cutover_verified: false,
    signature_verified: signatureVerified,
    eyebrow: signatureVerified ? "Offline receipt signature verified" : "Offline K0 bundle verified",
    headline: signatureVerified
      ? "Signature verified. Authenticated issuer output is not evidenced."
      : "Bundle verified. Authenticated issuer output is not evidenced.",
    summary: "The local read-only pending issuer exists and is tested, but this configured bundle, receipt, or signature does not prove that it ran against an authenticated fresh transaction. Release remains blocked.",
    recorded_at: manifest.assembled_at,
    checkpoint_sha256: receipt.manifest_sha256,
    metrics: [
      { value: "8/8", label: "hostile claims in bundle" },
      { value: "2/2", label: "WIF claims in bundle" },
      { value: "2/2", label: "legacy claims in bundle" },
      { value: String(manifest.evidence.length), label: "evidence artifacts" },
    ],
    gates: [
      gate("External v3 bundle", "passed", "Exact manifest and artifact bytes verified"),
      gate("Legacy baseline", "passed", manifest.legacy_baseline.revision),
      gate("Pending receipt", "passed", `Reconstructed ${receipt.receipt_id}`),
      gate("Pinned KMS signature", signatureVerified ? "passed" : "missing",
        signatureVerified ? "Exact pending receipt signature verified" : "External signature verification is not configured"),
      gate("Authenticated live pending issuance", "missing", "Local issuer exists; no authenticated live issuer output is configured or evidenced"),
      gate("Release authorization", "blocked", "RECOLLECTION_REQUIRED"),
    ],
    blockers: [
      ...(signatureVerified ? [] : ["After authenticated live pending issuance, separately authorize the scoped KMS signature and verify it against pinned trust."]),
      "Evidence from an authenticated live pending-issuer run is not configured; local implementation alone is not evidence.",
    ],
    sources,
    limitations: [
      ...manifest.limitations,
      "Offline bundle and signature verification do not prove that the local issuer ran against a fresh authenticated transaction.",
    ],
  };
}

export async function loadConsoleStatus(options = {}) {
  const checkpointPath = options.checkpointPath;
  const bundlePath = options.bundlePath;
  const receiptPath = options.receiptPath;
  const signaturePath = options.signaturePath;
  const legacyManifestPath = options.manifestPath;
  const trustAnchor = options.trustAnchor && typeof options.trustAnchor === "object"
    ? {
        key_version: options.trustAnchor.key_version,
        algorithm: options.trustAnchor.algorithm,
        public_key: options.trustAnchor.public_key,
      }
    : options.trustAnchor;
  const bundleConfigured = bundlePath !== undefined || legacyManifestPath !== undefined;
  const optionalConfigured = [receiptPath, signaturePath, options.trustAnchor].map((value) => value !== undefined);
  try {
    if (!bundleConfigured && optionalConfigured.every((configured) => !configured)) {
      if (!checkpointPath) throw new Error("checkpoint path is required");
      const { bytes, value } = await readBoundedJson(checkpointPath);
      return recordConsoleStatus(checkpointStatus(bytes, value));
    }
    if (typeof bundlePath !== "string" || !bundlePath || legacyManifestPath !== undefined
        || (optionalConfigured.some(Boolean) && !optionalConfigured.every(Boolean))) {
      throw new Error("configured K0 inputs are incomplete");
    }

    const bundlePromise = readK0BundleDirectory(resolve(bundlePath));
    if (!optionalConfigured.some(Boolean)) {
      const bundle = await bundlePromise;
      const { receipt } = await createK0Receipt(bundle);
      return recordConsoleStatus(bundleStatus(bundle, receipt, false));
    }
    if (typeof receiptPath !== "string" || !receiptPath
        || typeof signaturePath !== "string" || !signaturePath) {
      throw new Error("configured K0 inputs are invalid");
    }
    const [bundle, receiptBytes, sidecarBytes] = await Promise.all([
      bundlePromise,
      readBoundedFile(resolve(receiptPath), MAX_DOCUMENT_BYTES),
      readBoundedFile(resolve(signaturePath), MAX_SIDECAR_BYTES),
    ]);
    if (CREDENTIAL.test(receiptBytes.toString("utf8")) || CREDENTIAL.test(sidecarBytes.toString("utf8"))) {
      throw new Error("configured K0 inputs contain credential-shaped material");
    }
    await verifyK0Receipt({ receiptBytes, ...bundle });
    verifyKmsSignature(receiptBytes, sidecarBytes, trustAnchor);
    const { receipt } = await createK0Receipt(bundle);
    return recordConsoleStatus(bundleStatus(bundle, receipt, true));
  } catch {
    return recordConsoleStatus(failedStatus());
  }
}
