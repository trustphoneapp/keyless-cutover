import { assembleK0Bundle } from "../../src/k0-bundle.mjs";
import { validK0BundleInput } from "../fixtures/k0-bundle.mjs";

const FRAGMENT_FIELDS = [
  "scope", "revisions", "approved_workflows", "legacy_baseline", "proof", "cutover", "wif", "hostile_tests",
];

export async function validPreDisableArchiveInput() {
  const bundle = await assembleK0Bundle(validK0BundleInput());
  const fragment = Object.fromEntries(FRAGMENT_FIELDS.map((field) => [field, structuredClone(bundle.manifest[field])]));
  const ids = new Set([
    ...fragment.legacy_baseline.source_ids,
    ...fragment.proof.source_ids,
    ...fragment.cutover.source_ids,
    ...fragment.wif.source_ids,
    ...Object.values(fragment.approved_workflows).map(({ source_id: sourceId }) => sourceId),
    ...fragment.hostile_tests.flatMap(({ source_ids: sourceIds }) => sourceIds),
  ]);
  const evidence = bundle.manifest.evidence
    .filter(({ id }) => ids.has(id))
    .map(({ public_url: _publicUrl, ...entry }) => structuredClone(entry));
  return {
    plan: {
      version: 1,
      transaction_id: "example-transaction-1",
      nonce: "example-public-nonce-0001",
      scope: structuredClone(fragment.scope),
      fragment,
      evidence,
    },
    artifacts: new Map(evidence.map(({ id }) => [id, Buffer.from(bundle.artifacts.get(id))])),
  };
}
