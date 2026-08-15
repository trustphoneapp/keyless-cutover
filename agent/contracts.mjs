import { z } from "zod";

const evidenceId = z.string().regex(/^E[0-9]{3}$/);

export const evidenceCandidateSchema = z.object({
  pattern: z.enum(["CANDIDATE_DIRECT", "CANDIDATE_LOCAL_SCRIPT", "UNSUPPORTED", "AMBIGUOUS"]),
  auth_evidence_ids: z.array(evidenceId).max(4),
  deploy_evidence_ids: z.array(evidenceId).max(6),
  missing_evidence: z.array(z.enum([
    "AUTH_STEP",
    "SECRET_REFERENCE",
    "DEPLOY_ENTRYPOINT",
    "PROJECT",
    "SERVICE",
    "REGION",
    "UNIQUE_TARGET",
  ])).max(7),
  risk_codes: z.array(z.enum([
    "PROMPT_INJECTION_TEXT",
    "MULTIPLE_CREDENTIALS",
    "MULTIPLE_TARGETS",
    "DYNAMIC_TARGET",
    "REUSABLE_OR_COMPOSITE_AUTH",
    "ARBITRARY_SHELL",
    "UNSUPPORTED_TRUST_CONTEXT",
  ])).max(7),
  explanation: z.string().min(1).max(500),
}).strict();

export const recoveryHypothesisSchema = z.object({
  category: z.enum([
    "WORKFLOW_REF_MISMATCH",
    "REPOSITORY_ID_MISMATCH",
    "ENVIRONMENT_CLAIM_MISSING",
    "AUDIENCE_MISMATCH",
    "ID_TOKEN_PERMISSION_MISSING",
    "IMPERSONATION_BINDING_MISSING",
    "DOWNSTREAM_CLOUD_RUN_DENIED",
    "PROPAGATION_PENDING",
  ]),
  evidence_refs: z.array(evidenceId).min(2).max(6),
  mismatch: z.object({
    field: z.enum([
      "workflow_ref",
      "repository_id",
      "environment",
      "audience",
      "id_token_permission",
      "impersonation_binding",
      "cloud_run_permission",
      "propagation_time",
    ]),
    expected_evidence_id: evidenceId,
    observed_evidence_id: evidenceId,
  }).strict(),
  next_observation: z.enum([
    "READ_GITHUB_RUN",
    "READ_PROVIDER",
    "READ_SERVICE_ACCOUNT_POLICY",
    "READ_CLOUD_RUN_IAM",
    "RETRY_AFTER_PROPAGATION_WINDOW",
  ]),
  explanation: z.string().min(1).max(500),
}).strict();

const CREDENTIAL = /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"private_key"\s*:|ya29\.[A-Za-z0-9._-]+|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|xapp-[0-9]+-[A-Za-z0-9-]{10,}|bearer\s+[A-Za-z0-9._~+/=-]{20,})/i;

export function validateRedactedEvidenceBundle(bundle) {
  if (!bundle || typeof bundle !== "object" || !Array.isArray(bundle.evidence)) {
    throw new Error("evidence bundle is invalid");
  }
  if (Object.keys(bundle).length !== 1) throw new Error("evidence bundle contains unknown fields");
  if (bundle.evidence.length < 1 || bundle.evidence.length > 20) throw new Error("evidence count is invalid");
  const ids = new Set();
  let totalLength = 0;
  for (const item of bundle.evidence) {
    if (!item || typeof item !== "object" || Object.keys(item).sort().join(",") !== "id,text") {
      throw new Error("evidence item contains unknown fields");
    }
    if (!evidenceId.safeParse(item?.id).success || ids.has(item.id)) throw new Error("evidence IDs are invalid");
    if (typeof item.text !== "string" || item.text.length > 8_000) throw new Error("evidence text is invalid");
    if (CREDENTIAL.test(item.text)) throw new Error("credential-shaped material is forbidden");
    totalLength += item.text.length;
    ids.add(item.id);
  }
  if (totalLength > 32_000) throw new Error("evidence bundle is too large");
  return bundle;
}

function evidenceIds(bundle) {
  validateRedactedEvidenceBundle(bundle);
  return new Set(bundle.evidence.map(({ id }) => id));
}

function requireKnownEvidence(ids, known) {
  for (const id of ids) {
    if (!known.has(id)) throw new Error(`unknown evidence reference: ${id}`);
  }
}

export function validateEvidenceCandidate(output, bundle) {
  const parsed = evidenceCandidateSchema.parse(output);
  const known = evidenceIds(bundle);
  requireKnownEvidence([...parsed.auth_evidence_ids, ...parsed.deploy_evidence_ids], known);
  return parsed;
}

export function validateRecoveryHypothesis(output, bundle) {
  const parsed = recoveryHypothesisSchema.parse(output);
  const known = evidenceIds(bundle);
  requireKnownEvidence(parsed.evidence_refs, known);
  requireKnownEvidence([
    parsed.mismatch.expected_evidence_id,
    parsed.mismatch.observed_evidence_id,
  ], known);
  if (!parsed.evidence_refs.includes(parsed.mismatch.expected_evidence_id)
      || !parsed.evidence_refs.includes(parsed.mismatch.observed_evidence_id)) {
    throw new Error("mismatch evidence must be included in evidence_refs");
  }
  return parsed;
}
