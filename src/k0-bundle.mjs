import { canonicalJson, createEvidenceArtifact } from "./evidence-artifact.mjs";
import { verifyK0EvidenceSemantics } from "./k0-evidence-semantics.mjs";
import { verifyK0Manifest } from "./k0-manifest.mjs";

const INPUT_FIELDS = new Set(["manifest", "evidence"]);
const EVIDENCE_FIELDS = new Set(["id", "kind", "locator", "observed_at", "public_url", "data"]);

function exactObject(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).every((key) => fields.has(key));
}

function plainObject(value) {
  return value && typeof value === "object" && !Array.isArray(value);
}

export async function verifyK0Bundle({ manifest, artifacts }) {
  const structural = verifyK0Manifest(manifest);
  if (!structural.ok) throw new Error(structural.errors.join("\n"));
  if (!(artifacts instanceof Map)) throw new Error("evidence artifacts must be a Map");
  const expectedIds = new Set(manifest.evidence.map(({ id }) => id));
  if (artifacts.size !== expectedIds.size || [...artifacts.keys()].some((id) => !expectedIds.has(id))) {
    throw new Error("evidence artifacts do not exactly match the manifest ledger");
  }
  const semantic = await verifyK0EvidenceSemantics(manifest, async (id) => {
    if (!artifacts.has(id)) throw new Error("missing evidence artifact");
    return artifacts.get(id);
  });
  if (!semantic.ok) throw new Error(semantic.errors.join("\n"));
  return true;
}

export async function assembleK0Bundle(input) {
  if (!exactObject(input, INPUT_FIELDS) || !plainObject(input.manifest)
      || !Array.isArray(input.evidence) || input.manifest.evidence !== undefined) {
    throw new Error("K0 bundle input is invalid");
  }
  const manifest = structuredClone(input.manifest);
  const artifacts = new Map();
  const ledger = [];
  const byId = (left, right) => String(left?.id) < String(right?.id) ? -1 : String(left?.id) > String(right?.id) ? 1 : 0;
  for (const envelope of [...input.evidence].sort(byId)) {
    if (!exactObject(envelope, EVIDENCE_FIELDS)) throw new Error("evidence input fields are invalid");
    const created = createEvidenceArtifact(envelope);
    if (artifacts.has(envelope.id)) throw new Error(`${envelope.id} evidence is duplicated`);
    artifacts.set(envelope.id, Buffer.from(created.artifact));
    ledger.push({
      id: envelope.id,
      kind: envelope.kind,
      locator: envelope.locator,
      observed_at: envelope.observed_at,
      sha256: created.sha256,
      ...(envelope.public_url === undefined ? {} : { public_url: envelope.public_url }),
    });
  }
  manifest.evidence = ledger.sort(byId);
  await verifyK0Bundle({ manifest, artifacts });
  return { manifest, manifestBytes: Buffer.from(canonicalJson(manifest)), artifacts };
}
