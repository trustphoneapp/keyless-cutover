import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { assembleK0Bundle, verifyK0Bundle } from "../src/k0-bundle.mjs";
import { createCredentialScan } from "../src/credential-scan.mjs";
import { canonicalJson, createEvidenceArtifact, verifyEvidenceArtifacts } from "../src/evidence-artifact.mjs";
import { verifyK0EvidenceSemantics, verifyK0PreDisableEvidenceSemantics } from "../src/k0-evidence-semantics.mjs";
import { verifyK0Manifest, verifyK0PreDisableFragment } from "../src/k0-manifest.mjs";
import { createGcpEvidenceReader } from "../src/gcp-evidence.mjs";
import { computePreexistingWifParityHash } from "../src/gcp-evidence.mjs";
import {
  evidenceByKind,
  mutateCheckpointReceipt,
  refreshCheckpointReceipt,
  refreshFinalCredentialScan,
  validK0BundleInput,
  validWifAuditLog,
} from "./fixtures/k0-bundle.mjs";

const inactiveLegacyBytes = await readFile(new URL("../k0/templates/k0-deploy.legacy.yml", import.meta.url));
const inactiveLegacyBlobSha = createHash("sha1")
  .update(Buffer.from(`blob ${inactiveLegacyBytes.length}\0`)).update(inactiveLegacyBytes).digest("hex");
const inactiveLegacySha256 = createHash("sha256").update(inactiveLegacyBytes).digest("hex");
const PRE_DISABLE_FIELDS = [
  "scope", "revisions", "approved_workflows", "legacy_baseline", "proof", "cutover", "wif", "hostile_tests",
];

function preDisableCandidate(input) {
  const fragment = Object.fromEntries(PRE_DISABLE_FIELDS.map((field) => [field, structuredClone(input.manifest[field])]));
  const ids = new Set([
    ...fragment.legacy_baseline.source_ids,
    ...fragment.proof.source_ids,
    ...fragment.cutover.source_ids,
    ...fragment.wif.source_ids,
    ...Object.values(fragment.approved_workflows).map(({ source_id: sourceId }) => sourceId),
    ...fragment.hostile_tests.flatMap(({ source_ids: sourceIds }) => sourceIds),
  ]);
  const artifacts = new Map();
  const evidence = input.evidence.filter(({ id }) => ids.has(id)).map((envelope) => {
    const created = createEvidenceArtifact(envelope);
    artifacts.set(envelope.id, Buffer.from(created.artifact));
    return {
      id: envelope.id,
      kind: envelope.kind,
      locator: envelope.locator,
      observed_at: envelope.observed_at,
      sha256: created.sha256,
      ...(envelope.public_url === undefined ? {} : { public_url: envelope.public_url }),
    };
  }).toSorted((left, right) => left.id.localeCompare(right.id));
  return { fragment, evidence, artifacts };
}

function replaceArtifact(bundle, id, mutate) {
  const envelope = JSON.parse(bundle.artifacts.get(id).toString("utf8"));
  mutate(envelope);
  const created = createEvidenceArtifact(envelope);
  bundle.artifacts.set(id, Buffer.from(created.artifact));
  const ledger = bundle.manifest.evidence.find((entry) => entry.id === id);
  ledger.kind = envelope.kind;
  ledger.locator = envelope.locator;
  ledger.observed_at = envelope.observed_at;
  ledger.sha256 = created.sha256;
}

async function semanticResult(bundle) {
  return verifyK0EvidenceSemantics(bundle.manifest, async (id) => bundle.artifacts.get(id));
}

test("offline assembler creates one canonical, fully verified K0 bundle", async () => {
  const input = validK0BundleInput();
  const bundle = await assembleK0Bundle(input);
  assert.deepEqual(verifyK0Manifest(bundle.manifest), { ok: true, errors: [] });
  assert.deepEqual(
    await verifyEvidenceArtifacts(bundle.manifest, async (id) => bundle.artifacts.get(id)),
    { ok: true, errors: [] },
  );
  assert.deepEqual(
    await verifyK0EvidenceSemantics(bundle.manifest, async (id) => bundle.artifacts.get(id)),
    { ok: true, errors: [] },
  );
  assert.equal(bundle.manifestBytes.toString("utf8"), canonicalJson(bundle.manifest));
  assert.equal(bundle.artifacts.size, bundle.manifest.evidence.length);
  assert.equal(bundle.manifest.version, 3);
  assert.deepEqual(bundle.manifest.approved_workflows.baseline, {
    workflow_path: ".github/workflows/k0-deploy.yml",
    workflow_blob_sha: inactiveLegacyBlobSha,
    workflow_sha256: inactiveLegacySha256,
    source_id: bundle.manifest.approved_workflows.baseline.source_id,
  });
  for (const name of ["wif-1-revision", "wif-2-revision"]) {
    const revision = evidenceByKind(input, "CLOUD_RUN_REVISION", name).data;
    assert.equal(["run_id", "run_attempt", "head_sha", "project_number"].some((field) => field in revision), false);
  }
});

test("shared pre-disable verifier accepts only the exact complete fragment", async () => {
  const candidate = preDisableCandidate(validK0BundleInput());
  assert.deepEqual(verifyK0PreDisableFragment(candidate.fragment, candidate.evidence), { ok: true, errors: [] });
  const calls = new Map();
  assert.deepEqual(await verifyK0PreDisableEvidenceSemantics(
    candidate.fragment,
    candidate.evidence,
    async (id) => {
      calls.set(id, (calls.get(id) ?? 0) + 1);
      return candidate.artifacts.get(id);
    },
  ), { ok: true, errors: [] });
  assert.equal([...calls.values()].every((count) => count === 1), true);

  for (const field of ["checkpoint", "disable", "legacy_after_disable", "post_disable", "final"]) {
    const changed = structuredClone(candidate.fragment);
    changed[field] = {};
    assert.equal(verifyK0PreDisableFragment(changed, candidate.evidence).ok, false, field);
    assert.equal((await verifyK0PreDisableEvidenceSemantics(
      changed,
      candidate.evidence,
      async (id) => candidate.artifacts.get(id),
    )).ok, false, field);
  }
  const extraEvidence = [...candidate.evidence, { ...candidate.evidence[0], id: "E099" }];
  assert.equal(verifyK0PreDisableFragment(candidate.fragment, extraEvidence).ok, false);
  assert.equal(verifyK0PreDisableFragment(candidate.fragment, [...candidate.evidence, candidate.evidence[0]]).ok, false);
  const missingSection = structuredClone(candidate.fragment);
  delete missingSection.legacy_baseline;
  assert.equal(verifyK0PreDisableFragment(missingSection, candidate.evidence).ok, false);

  const full = await assembleK0Bundle(validK0BundleInput());
  const incomplete = structuredClone(full.manifest);
  for (const field of ["checkpoint", "disable", "legacy_after_disable", "post_disable", "leak_scan"]) delete incomplete[field];
  assert.equal(verifyK0Manifest(incomplete).ok, false);
  await assert.rejects(() => verifyK0Bundle({ manifest: incomplete, artifacts: full.artifacts }));
});

test("shared and full verifiers reject the same pre-disable attacks", async () => {
  const attacks = [
    ["proof key state", (input) => { evidenceByKind(input, "GCP_IAM_KEY", "proof-key").data.disabled = true; }],
    ["proof binding", (input) => { evidenceByKind(input, "PROOFV2_ARTIFACT").data.run_attempt = "2"; }],
    ["proof event", (input) => { evidenceByKind(input, "GITHUB_RUN", "proof-run").data.event = "push"; }],
    ["proof review actor", (input) => { evidenceByKind(input, "GITHUB_ENVIRONMENT_REVIEW", "proof-review").data.actor_id = "999"; }],
    ["proof state missing", (input) => {
      const stateId = evidenceByKind(input, "PROOFV2_CHALLENGE_STATE").id;
      input.manifest.proof.source_ids = input.manifest.proof.source_ids.filter((id) => id !== stateId);
    }],
    ["proof state status", (input) => { evidenceByKind(input, "PROOFV2_CHALLENGE_STATE").data.status = "ISSUED"; }],
    ["proof state digest", (input) => { evidenceByKind(input, "PROOFV2_CHALLENGE_STATE").data.proof_digest = "f".repeat(64); }],
    ["proof state scope", (input) => { evidenceByKind(input, "PROOFV2_CHALLENGE_STATE").data.owner_id = "999"; }],
    ["proof state run", (input) => { evidenceByKind(input, "PROOFV2_CHALLENGE_STATE").data.run_id = "999"; }],
    ["proof state key", (input) => { evidenceByKind(input, "PROOFV2_CHALLENGE_STATE").data.key_id = "f".repeat(40); }],
    ["proof state receipt", (input) => { evidenceByKind(input, "PROOFV2_CHALLENGE_STATE").data.receipt_sha256 = "f".repeat(64); }],
    ["proof state time", (input) => {
      evidenceByKind(input, "PROOFV2_CHALLENGE_STATE").data.update_time = "2026-08-13T11:31:59Z";
    }],
    ["proof state backdated observation", (input) => {
      evidenceByKind(input, "PROOFV2_CHALLENGE_STATE").observed_at = "2026-08-13T11:32:00Z";
    }],
    ["baseline key", (input) => {
      const key = evidenceByKind(input, "GCP_IAM_KEY", "legacy-baseline-key").data;
      key.key_id = "b".repeat(40);
      key.name = `projects/-/serviceAccounts/${input.manifest.scope.service_account_email}/keys/${key.key_id}`;
    }],
    ["baseline workflow", (input) => { evidenceByKind(input, "GITHUB_RUN", "legacy-baseline").data.workflow_sha256 = "9".repeat(64); }],
    ["baseline run", (input) => { input.manifest.legacy_baseline.run_id = "9999"; }],
    ["baseline self review", (input) => {
      evidenceByKind(input, "GITHUB_ENVIRONMENT_REVIEW", "legacy-baseline-review").data.reviewer_id = "10";
    }],
    ["baseline release", (input) => { input.manifest.legacy_baseline.release_marker = "wrong"; }],
    ["baseline revision", (input) => {
      evidenceByKind(input, "CLOUD_RUN_REVISION", "legacy-baseline-revision").data.revision = "wrong-00001";
    }],
    ["baseline stale revision", (input) => {
      evidenceByKind(input, "CLOUD_RUN_REVISION", "legacy-baseline-revision").data.create_time = "2026-08-13T10:45:59Z";
    }],
    ["baseline after wif-1", (input) => {
      const run = evidenceByKind(input, "GITHUB_RUN", "legacy-baseline");
      const revision = evidenceByKind(input, "CLOUD_RUN_REVISION", "legacy-baseline-revision");
      run.data.started_at = "2026-08-13T11:31:30Z";
      run.observed_at = "2026-08-13T11:33:00Z";
      revision.data.create_time = "2026-08-13T11:32:00Z";
      revision.observed_at = "2026-08-13T11:33:00Z";
    }],
    ["cutover repository", (input) => { evidenceByKind(input, "GITHUB_PULL_REQUEST", "cutover-pr").data.repository_id = "999"; }],
    ["wif-1 self review", (input) => { evidenceByKind(input, "GITHUB_ENVIRONMENT_REVIEW", "wif-1-review").data.reviewer_id = "10"; }],
    ["wif-1 stale revision", (input) => {
      evidenceByKind(input, "CLOUD_RUN_REVISION", "wif-1-revision").data.create_time = "2026-08-13T11:29:59Z";
    }],
    ["wif-1 project", (input) => {
      evidenceByKind(input, "CLOUD_RUN_REVISION", "wif-1-revision").data.project_id = "wrong-project";
    }],
    ["WIF project", (input) => { evidenceByKind(input, "GCP_WIF_PARITY").data.project_number = "999"; }],
    ["WIF parity mode", (input) => { input.manifest.wif.mode = "ADDITIVE"; }],
    ["WIF parity observation inversion", (input) => {
      const parity = evidenceByKind(input, "GCP_WIF_PARITY").data;
      [parity.observed_before_at, parity.observed_after_at] = [parity.observed_after_at, parity.observed_before_at];
      parity.parity_hash = computePreexistingWifParityHash(parity);
      input.manifest.wif.parity_hash = parity.parity_hash;
    }],
    ["WIF etag hash substitution", (input) => {
      evidenceByKind(input, "GCP_WIF_PARITY").data.allowed_etag_sha256 = "9".repeat(64);
    }],
    ["WIF raw etag field", (input) => {
      evidenceByKind(input, "GCP_WIF_PARITY").data.allowed_policy_before_etag = "opaque";
    }],
    ["WIF coherent parity substitution", (input) => {
      const parity = evidenceByKind(input, "GCP_WIF_PARITY").data;
      parity.project_id = "wrong-project";
      parity.parity_hash = computePreexistingWifParityHash(parity);
      input.manifest.wif.parity_hash = parity.parity_hash;
    }],
    ["WIF coherent region substitution", (input) => {
      const parity = evidenceByKind(input, "GCP_WIF_PARITY").data;
      parity.region = "us-east1";
      parity.parity_hash = computePreexistingWifParityHash(parity);
      input.manifest.wif.parity_hash = parity.parity_hash;
    }],
    ["WIF allowed and forbidden service substitution", (input) => {
      const parity = evidenceByKind(input, "GCP_WIF_PARITY").data;
      [parity.allowed_service, parity.forbidden_service] = [parity.forbidden_service, parity.allowed_service];
      parity.parity_hash = computePreexistingWifParityHash(parity);
      input.manifest.wif.parity_hash = parity.parity_hash;
    }],
    ["old additive WIF artifact", (input) => {
      const parity = evidenceByKind(input, "GCP_WIF_PARITY");
      parity.kind = "GCP_WIF_PROVIDER";
      parity.data = {
        name: input.manifest.wif.provider,
        config_hash: input.manifest.wif.config_hash,
        state: "ACTIVE",
        project_id: input.manifest.scope.project_id,
        project_number: input.manifest.scope.project_number,
        service_account_email: input.manifest.scope.service_account_email,
        service_account_unique_id: input.manifest.scope.service_account_unique_id,
      };
    }],
    ["H1 path", (input) => {
      evidenceByKind(input, "GITHUB_RUN", "H1-run").data.workflow_path = input.manifest.scope.h2_workflow_path;
    }],
    ["H1 late approval", (input) => {
      const approval = evidenceByKind(input, "GITHUB_PULL_REQUEST", "h1-workflow-approval");
      approval.data.reviewed_at = "2026-08-13T11:51:00Z";
      approval.data.merged_at = "2026-08-13T11:52:00Z";
      approval.observed_at = "2026-08-13T11:53:00Z";
    }],
    ["H2 late approval", (input) => {
      const approval = evidenceByKind(input, "GITHUB_PULL_REQUEST", "h2-workflow-approval");
      approval.data.reviewed_at = "2026-08-13T11:49:00Z";
      approval.data.merged_at = "2026-08-13T11:51:00Z";
      approval.observed_at = "2026-08-13T11:52:00Z";
    }],
    ["H1 H2 approval swap", (input) => {
      const h1 = input.manifest.approved_workflows.h1.source_id;
      input.manifest.approved_workflows.h1.source_id = input.manifest.approved_workflows.h2.source_id;
      input.manifest.approved_workflows.h2.source_id = h1;
    }],
    ["H7 workflow", (input) => { evidenceByKind(input, "GITHUB_RUN", "H7-run").data.workflow_sha256 = "9".repeat(64); }],
    ["legacy approval", (input) => { input.manifest.approved_workflows.legacy.workflow_sha256 = "9".repeat(64); }],
    ["forbidden region", (input) => {
      evidenceByKind(input, "CLOUD_RUN_REVISION", "forbidden-before").data.region = "us-east1";
    }],
    ["backdated observation", (input) => {
      evidenceByKind(input, "STS_CLIENT_RESULT", "H1-result").observed_at = "2026-08-13T11:49:59Z";
    }],
    ["H8 bracket", (input) => {
      evidenceByKind(input, "CLOUD_RUN_REVISION", "forbidden-after-hostile").observed_at = "2026-08-13T11:40:00Z";
    }],
    ["hostile source count", (input) => { input.manifest.hostile_tests[7].source_ids.pop(); }],
    ["forbidden source identity", (input) => {
      input.manifest.revisions.forbidden_after_hostile_source_id = input.manifest.revisions.forbidden_before_source_id;
    }],
    ["missing baseline source", (input) => { input.manifest.legacy_baseline.source_ids.pop(); }],
  ];
  for (const [label, mutate] of attacks) {
    const input = validK0BundleInput();
    mutate(input);
    refreshCheckpointReceipt(input);
    if (label === "H8 bracket") {
      const id = evidenceByKind(input, "CLOUD_RUN_REVISION", "forbidden-after-hostile").id;
      mutateCheckpointReceipt(input, (receipt) => {
        receipt.evidence.find((record) => record.id === id).recorded_at = "2026-08-13T11:40:00Z";
      });
    }
    const candidate = preDisableCandidate(input);
    assert.equal((await verifyK0PreDisableEvidenceSemantics(
      candidate.fragment,
      candidate.evidence,
      async (id) => candidate.artifacts.get(id),
    )).ok, false, `shared: ${label}`);
    await assert.rejects(() => assembleK0Bundle(input), undefined, `full: ${label}`);
  }
});

test("authoritative Cloud Run wif-1 and wif-2 readbacks feed the assembler unchanged", async () => {
  const input = validK0BundleInput();
  const collect = async (revision, releaseMarker, createTime) => createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async (url) => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(url.includes("/revisions/") ? {
        name: `projects/${input.manifest.scope.project_id}/locations/${input.manifest.scope.region}/services/${input.manifest.scope.allowed_service}/revisions/${revision}`,
        createTime,
        containers: [{
          image: `us-docker.pkg.dev/example/app@sha256:${"a".repeat(64)}`,
          env: [{ name: "RELEASE", value: releaseMarker }],
        }],
      } : { latestReadyRevision: revision }),
    }),
  }).readCloudRunRevision({
    projectId: input.manifest.scope.project_id,
    region: input.manifest.scope.region,
    service: input.manifest.scope.allowed_service,
  });
  evidenceByKind(input, "CLOUD_RUN_REVISION", "wif-1-revision").data = await collect(
    input.manifest.revisions.wif_1,
    input.manifest.cutover.wif_1_release_marker,
    "2026-08-13T11:31:00Z",
  );
  evidenceByKind(input, "CLOUD_RUN_REVISION", "wif-2-revision").data = await collect(
    input.manifest.revisions.wif_2,
    input.manifest.post_disable.release_marker,
    "2026-08-13T12:13:45Z",
  );
  const audit = JSON.parse(validWifAuditLog(input.manifest));
  const auditReader = createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async () => ({ ok: true, status: 200, text: async () => JSON.stringify(audit) }),
  });
  evidenceByKind(input, "GCP_WIF_AUDIT_LOG").data = JSON.parse(await auditReader.readWifAuditEvidence({
    projectId: input.manifest.scope.project_id,
    provider: input.manifest.wif.provider,
    serviceAccountEmail: input.manifest.scope.service_account_email,
    serviceAccountUniqueId: input.manifest.scope.service_account_unique_id,
    startTime: "2026-08-13T12:13:00Z",
    endTime: "2026-08-13T12:14:00Z",
  }));
  refreshCheckpointReceipt(input);
  await assembleK0Bundle(input);
});

test("assembler orders artifact maps deterministically and accepts only bound Google key resource variants", async () => {
  const reversed = validK0BundleInput();
  reversed.evidence.reverse();
  const ordered = await assembleK0Bundle(reversed);
  assert.deepEqual([...ordered.artifacts.keys()], [...ordered.artifacts.keys()].toSorted());

  const base = validK0BundleInput();
  const scope = base.manifest.scope;
  const names = [
    `projects/-/serviceAccounts/${scope.service_account_email}/keys/${scope.key_id}`,
    `projects/${scope.project_id}/serviceAccounts/${scope.service_account_email}/keys/${scope.key_id}`,
    `projects/-/serviceAccounts/${scope.service_account_unique_id}/keys/${scope.key_id}`,
    `projects/${scope.project_id}/serviceAccounts/${scope.service_account_unique_id}/keys/${scope.key_id}`,
  ];
  for (const name of names) {
    const input = validK0BundleInput();
    evidenceByKind(input, "GCP_IAM_KEY", "proof-key").data.name = name;
    refreshCheckpointReceipt(input);
    refreshFinalCredentialScan(input);
    await assembleK0Bundle(input);
  }
  const wrong = validK0BundleInput();
  evidenceByKind(wrong, "GCP_IAM_KEY", "proof-key").data.name = `projects/wrong-project/serviceAccounts/${scope.service_account_email}/keys/${scope.key_id}`;
  await assert.rejects(() => assembleK0Bundle(wrong), /resource/);
});

test("strict post-disable and scope contracts reject false-safe evidence", async () => {
  const mutations = [
    ["obsolete v2 contract", (input) => { input.manifest.version = 2; }],
    ["missing legacy baseline", (input) => { delete input.manifest.legacy_baseline; }],
    ["legacy baseline key", (input) => {
      const key = evidenceByKind(input, "GCP_IAM_KEY", "legacy-baseline-key").data;
      key.key_id = "b".repeat(40);
      key.name = `projects/-/serviceAccounts/${input.manifest.scope.service_account_email}/keys/${key.key_id}`;
      refreshCheckpointReceipt(input);
    }],
    ["legacy baseline workflow", (input) => {
      const run = evidenceByKind(input, "GITHUB_RUN", "legacy-baseline").data;
      run.workflow_blob_sha = "9".repeat(40);
      run.workflow_sha256 = "9".repeat(64);
      refreshCheckpointReceipt(input);
    }],
    ["legacy baseline run", (input) => { input.manifest.legacy_baseline.run_id = "9999"; }],
    ["missing legacy baseline source", (input) => { input.manifest.legacy_baseline.source_ids.pop(); }],
    ["legacy baseline reviewer", (input) => {
      evidenceByKind(input, "GITHUB_ENVIRONMENT_REVIEW", "legacy-baseline-review").data.reviewer_id = "10";
    }],
    ["legacy baseline release", (input) => { input.manifest.legacy_baseline.release_marker = "wrong"; }],
    ["legacy baseline revision", (input) => {
      evidenceByKind(input, "CLOUD_RUN_REVISION", "legacy-baseline-revision").data.revision = "wrong-00001";
      refreshCheckpointReceipt(input);
    }],
    ["uncheckpointed legacy baseline", (input) => {
      const id = input.manifest.legacy_baseline.source_ids[0];
      mutateCheckpointReceipt(input, (receipt) => {
        receipt.evidence = receipt.evidence.filter((record) => record.id !== id);
      });
    }],
    ["legacy key", (input) => { evidenceByKind(input, "GOOGLE_AUTH_RESULT").data.key_id = "b".repeat(40); }],
    ["legacy run", (input) => { evidenceByKind(input, "GOOGLE_AUTH_RESULT").data.run_id = "9999"; }],
    ["legacy attempt", (input) => { evidenceByKind(input, "GOOGLE_AUTH_RESULT").data.run_attempt = "2"; }],
    ["legacy SHA", (input) => { evidenceByKind(input, "GOOGLE_AUTH_RESULT").data.head_sha = "1".repeat(40); }],
    ["legacy owner", (input) => { evidenceByKind(input, "GOOGLE_AUTH_RESULT").data.owner_id = "999"; }],
    ["legacy workflow", (input) => { evidenceByKind(input, "GOOGLE_AUTH_RESULT").data.workflow_path = input.manifest.scope.workflow_path; }],
    ["legacy workflow ref", (input) => { evidenceByKind(input, "GOOGLE_AUTH_RESULT").data.workflow_ref = "owner/repo/.github/workflows/wrong.yml@refs/heads/main"; }],
    ["legacy ref", (input) => { evidenceByKind(input, "GOOGLE_AUTH_RESULT").data.ref = "refs/heads/wrong"; }],
    ["legacy Google reach", (input) => { evidenceByKind(input, "GOOGLE_AUTH_RESULT").data.reached_google = false; }],
    ["legacy category", (input) => { evidenceByKind(input, "GOOGLE_AUTH_RESULT").data.rejection_category = "NETWORK_ERROR"; }],
    ["stale legacy", (input) => { evidenceByKind(input, "GOOGLE_AUTH_RESULT").data.rejected_at = "2026-08-13T12:09:59Z"; }],
    ["synthesized WIF run", (input) => { evidenceByKind(input, "GCP_WIF_AUDIT_LOG").data.run_id = "9999"; }],
    ["wif-2 run", (input) => { evidenceByKind(input, "GITHUB_RUN", "wif-2").data.run_id = "9999"; }],
    ["wif-2 attempt", (input) => { evidenceByKind(input, "GITHUB_RUN", "wif-2").data.run_attempt = "2"; }],
    ["wif-2 SHA", (input) => { evidenceByKind(input, "GITHUB_RUN", "wif-2").data.head_sha = "1".repeat(40); }],
    ["wif-2 unbound review", (input) => { evidenceByKind(input, "GITHUB_ENVIRONMENT_REVIEW", "wif-2-review").data.run_id = "9999"; }],
    ["wif-1 self review", (input) => { evidenceByKind(input, "GITHUB_ENVIRONMENT_REVIEW", "wif-1-review").data.reviewer_id = "10"; }],
    ["wif-2 provider", (input) => { evidenceByKind(input, "GCP_WIF_AUDIT_LOG").data.entries[0].protoPayload.resourceName += "-wrong"; }],
    ["wif-2 project", (input) => { evidenceByKind(input, "GCP_WIF_AUDIT_LOG").data.entries[0].resource.labels.project_id = "wrong-project"; }],
    ["wif-2 service account", (input) => { evidenceByKind(input, "GCP_WIF_AUDIT_LOG").data.entries[1].resource.labels.email_id = "wrong@example.iam.gserviceaccount.com"; }],
    ["wif-2 service account ID", (input) => { evidenceByKind(input, "GCP_WIF_AUDIT_LOG").data.entries[1].resource.labels.unique_id = "999"; }],
    ["wif-2 IdP subject", (input) => { evidenceByKind(input, "GCP_WIF_AUDIT_LOG").data.entries[0].protoPayload.authenticationInfo.principalSubject = "wrong"; }],
    ["wif-2 mapped principal", (input) => { evidenceByKind(input, "GCP_WIF_AUDIT_LOG").data.entries[0].protoPayload.metadata.mapped_principal = "wrong"; }],
    ["stale wif-2", (input) => {
      const entries = evidenceByKind(input, "GCP_WIF_AUDIT_LOG").data.entries;
      entries[0].timestamp = "2026-08-13T12:09:58Z";
      entries[1].timestamp = "2026-08-13T12:09:59Z";
    }],
    ["pre-run STS exchange", (input) => {
      evidenceByKind(input, "GCP_WIF_AUDIT_LOG").data.entries[0].timestamp = "2026-08-13T12:12:59Z";
    }],
    ["wif-2 revision", (input) => { evidenceByKind(input, "CLOUD_RUN_REVISION", "wif-2-revision").data.revision = "wrong-00001"; }],
    ["synthesized Cloud run attribution", (input) => { evidenceByKind(input, "CLOUD_RUN_REVISION", "wif-2-revision").data.run_id = "3002"; }],
    ["wif-2 region", (input) => { evidenceByKind(input, "CLOUD_RUN_REVISION", "wif-2-revision").data.region = "us-east1"; }],
    ["missing wif-2 image digest", (input) => { evidenceByKind(input, "CLOUD_RUN_REVISION", "wif-2-revision").data.image_digest = null; }],
    ["pre-existing wif-2 revision", (input) => { evidenceByKind(input, "CLOUD_RUN_REVISION", "wif-2-revision").data.create_time = "2026-08-13T12:12:59Z"; }],
    ["pre-existing wif-1 revision", (input) => { evidenceByKind(input, "CLOUD_RUN_REVISION", "wif-1-revision").data.create_time = "2026-08-13T11:29:59Z"; }],
    ["wrong-run release marker", (input) => { evidenceByKind(input, "GITHUB_RUN", "wif-2").data.release_marker = "wrong-run"; }],
    ["wif-1 project", (input) => { evidenceByKind(input, "CLOUD_RUN_REVISION", "wif-1-revision").data.project_id = "wrong-project"; }],
    ["forbidden region", (input) => { evidenceByKind(input, "CLOUD_RUN_REVISION", "forbidden-before").data.region = "us-east1"; }],
    ["early wif-2 revision", (input) => { evidenceByKind(input, "CLOUD_RUN_REVISION", "wif-2-revision").observed_at = "2026-08-13T12:09:59Z"; }],
    ["disable actor", (input) => { evidenceByKind(input, "GCP_AUDIT_ENTRY").data.principal_email = "other@example.com"; }],
    ["disable service account", (input) => { evidenceByKind(input, "GCP_AUDIT_ENTRY").data.service_account_unique_id = "999"; }],
    ["disable method", (input) => { evidenceByKind(input, "GCP_AUDIT_ENTRY").data.method_name = "DeleteServiceAccountKey"; }],
    ["disable status", (input) => { evidenceByKind(input, "GCP_AUDIT_ENTRY").data.status = "FAILED"; }],
    ["cutover repository", (input) => { evidenceByKind(input, "GITHUB_PULL_REQUEST", "cutover-pr").data.repository_id = "999"; }],
    ["unapproved legacy bytes", (input) => { evidenceByKind(input, "GITHUB_RUN", "legacy-denied").data.workflow_sha256 = "9".repeat(64); }],
    ["unapproved H7 bytes", (input) => { evidenceByKind(input, "GITHUB_RUN", "H7-run").data.workflow_sha256 = "9".repeat(64); }],
    ["self-asserted legacy approval", (input) => { input.manifest.approved_workflows.legacy.workflow_sha256 = "9".repeat(64); }],
    ["proof run binding", (input) => { evidenceByKind(input, "PROOFV2_ARTIFACT").data.run_attempt = "2"; }],
    ["proof event", (input) => { evidenceByKind(input, "GITHUB_RUN", "proof-run").data.event = "push"; }],
    ["proof review actor", (input) => { evidenceByKind(input, "GITHUB_ENVIRONMENT_REVIEW").data.actor_id = "999"; }],
    ["project drift", (input) => { evidenceByKind(input, "GCP_WIF_PARITY").data.project_number = "999"; }],
    ["unbracketed forbidden observation", (input) => { evidenceByKind(input, "CLOUD_RUN_REVISION", "forbidden-after").observed_at = "2026-08-13T12:13:44Z"; }],
    ["H1 path swapped with H2", (input) => {
      evidenceByKind(input, "GITHUB_RUN", "H1-run").data.workflow_path = input.manifest.scope.h2_workflow_path;
    }],
    ["H1/H2 approvals swapped", (input) => {
      const h1 = input.manifest.approved_workflows.h1.source_id;
      input.manifest.approved_workflows.h1.source_id = input.manifest.approved_workflows.h2.source_id;
      input.manifest.approved_workflows.h2.source_id = h1;
    }],
    ["early post event", (input) => { evidenceByKind(input, "GITHUB_RUN", "wif-2").data.started_at = "2026-08-13T12:09:59Z"; }],
    ["occurrence after observation", (input) => { evidenceByKind(input, "GOOGLE_AUTH_RESULT").data.rejected_at = "2026-08-13T12:12:00.000000001Z"; }],
    ["observation after assembly", (input) => { input.manifest.assembled_at = "2026-08-13T12:15:00Z"; }],
    ["over 48 hours", (input) => { input.manifest.assembled_at = "2026-08-15T12:00:00Z"; }],
    ["consistent post workflow drift", (input) => {
      const sha = "1".repeat(40);
      input.manifest.post_disable.head_sha = sha;
      const run = evidenceByKind(input, "GITHUB_RUN", "wif-2");
      run.data.head_sha = sha;
      run.data.workflow_sha256 = "1".repeat(64);
      run.data.workflow_blob_sha = "1".repeat(40);
    }],
    ["extra payload field", (input) => { evidenceByKind(input, "GOOGLE_AUTH_RESULT").data.untrusted = true; }],
    ["unreferenced evidence", (input) => { input.evidence.push({ ...structuredClone(input.evidence.at(-1)), id: "E099" }); }],
    ["duplicate evidence", (input) => { input.evidence.push(structuredClone(input.evidence.at(-1))); }],
  ];
  for (const [label, mutate] of mutations) {
    const input = validK0BundleInput();
    mutate(input);
    await assert.rejects(() => assembleK0Bundle(input), undefined, label);
  }
});

test("checkpoint timing uses authoritative occurrences and permits late authenticated recollection", async () => {
  const late = validK0BundleInput();
  const preDisableIds = new Set(JSON.parse(Buffer.from(
    evidenceByKind(late, "GITHUB_EVIDENCE_CHECKPOINT").data.receipt.bytes_base64,
    "base64",
  )).evidence.map(({ id }) => id));
  for (const item of late.evidence) {
    if (preDisableIds.has(item.id)) item.observed_at = "2026-08-13T12:18:30Z";
  }
  refreshFinalCredentialScan(late);
  await assembleK0Bundle(late);

  const attacks = [
    ["backdated observation", (input) => {
      evidenceByKind(input, "STS_CLIENT_RESULT", "H1-result").observed_at = "2026-08-13T11:49:59Z";
    }],
    ["pre-disable event after disable", (input) => {
      evidenceByKind(input, "STS_CLIENT_RESULT", "H1-result").data.denied_at = "2026-08-13T12:10:01Z";
      refreshCheckpointReceipt(input);
    }],
    ["H1 approval reviewed after run and denial", (input) => {
      const approval = evidenceByKind(input, "GITHUB_PULL_REQUEST", "h1-workflow-approval");
      approval.data.reviewed_at = "2026-08-13T11:51:00Z";
      approval.data.merged_at = "2026-08-13T11:52:00Z";
      approval.observed_at = "2026-08-13T12:00:00Z";
      refreshCheckpointReceipt(input);
      mutateCheckpointReceipt(input, (receipt) => {
        receipt.evidence.find(({ id }) => id === approval.id).recorded_at = "2026-08-13T11:53:00Z";
      });
    }],
    ["H2 approval merged after run and denial", (input) => {
      const approval = evidenceByKind(input, "GITHUB_PULL_REQUEST", "h2-workflow-approval");
      approval.data.reviewed_at = "2026-08-13T11:49:00Z";
      approval.data.merged_at = "2026-08-13T11:51:00Z";
      approval.observed_at = "2026-08-13T12:00:00Z";
      refreshCheckpointReceipt(input);
      mutateCheckpointReceipt(input, (receipt) => {
        receipt.evidence.find(({ id }) => id === approval.id).recorded_at = "2026-08-13T11:52:00Z";
      });
    }],
    ["post-disable event before disable", (input) => {
      evidenceByKind(input, "GITHUB_RUN", "wif-2").data.started_at = "2026-08-13T12:09:59Z";
    }],
    ["uncheckpointed historical fact", (input) => {
      mutateCheckpointReceipt(input, (receipt) => { receipt.evidence.pop(); });
    }],
    ["H8 not bracketed by reviewed records", (input) => {
      const id = evidenceByKind(input, "CLOUD_RUN_REVISION", "forbidden-after-hostile").id;
      mutateCheckpointReceipt(input, (receipt) => {
        receipt.evidence.find((record) => record.id === id).recorded_at = "2026-08-13T11:40:00Z";
      });
    }],
    ["assembly after 48-hour deadline", (input) => { input.manifest.assembled_at = "2026-08-15T12:00:00Z"; }],
  ];
  for (const [label, mutate] of attacks) {
    const input = validK0BundleInput();
    mutate(input);
    await assert.rejects(() => assembleK0Bundle(input), undefined, label);
  }
});

test("fresh legacy rejection strictly precedes the complete wif-2 transaction", async () => {
  const moveWif2 = (input, startedAt) => {
    const legacyResult = evidenceByKind(input, "GOOGLE_AUTH_RESULT", "legacy-auth");
    const run = evidenceByKind(input, "GITHUB_RUN", "wif-2");
    const review = evidenceByKind(input, "GITHUB_ENVIRONMENT_REVIEW", "wif-2-review");
    const audit = evidenceByKind(input, "GCP_WIF_AUDIT_LOG", "wif-2-audit");
    const revision = evidenceByKind(input, "CLOUD_RUN_REVISION", "wif-2-revision");
    legacyResult.data.rejected_at = "2026-08-13T12:11:35Z";
    legacyResult.observed_at = "2026-08-13T12:12:10Z";
    run.data.started_at = startedAt;
    audit.data.entries[0].timestamp = "2026-08-13T12:11:40Z";
    audit.data.entries[1].timestamp = "2026-08-13T12:11:50Z";
    revision.data.create_time = "2026-08-13T12:12:00Z";
    for (const item of [run, review, audit, revision]) item.observed_at = "2026-08-13T12:12:10Z";
    refreshFinalCredentialScan(input);
  };

  for (const [label, startedAt] of [
    ["wif-2 starts before legacy rejection", "2026-08-13T12:11:34.999999999Z"],
    ["wif-2 starts exactly at legacy rejection", "2026-08-13T12:11:35Z"],
  ]) {
    const input = validK0BundleInput();
    moveWif2(input, startedAt);
    await assert.rejects(
      () => assembleK0Bundle(input),
      /fresh legacy denial must strictly precede post-disable WIF run/,
      label,
    );
  }

  const validBoundary = validK0BundleInput();
  moveWif2(validBoundary, "2026-08-13T12:11:35.000000001Z");
  await assembleK0Bundle(validBoundary);
});

test("legacy baseline must be fresh, checkpointed, and strictly before wif-1", async () => {
  const attacks = [
    ["stale pre-run revision", (input) => {
      evidenceByKind(input, "CLOUD_RUN_REVISION", "legacy-baseline-revision").data.create_time = "2026-08-13T10:45:59Z";
      refreshCheckpointReceipt(input);
    }],
    ["baseline after wif-1", (input) => {
      const run = evidenceByKind(input, "GITHUB_RUN", "legacy-baseline");
      const revision = evidenceByKind(input, "CLOUD_RUN_REVISION", "legacy-baseline-revision");
      run.data.started_at = "2026-08-13T11:31:30Z";
      run.observed_at = "2026-08-13T11:33:00Z";
      revision.data.create_time = "2026-08-13T11:32:00Z";
      revision.observed_at = "2026-08-13T11:33:00Z";
      refreshCheckpointReceipt(input);
      mutateCheckpointReceipt(input, (receipt) => {
        for (const id of [run.id, revision.id]) {
          receipt.evidence.find((record) => record.id === id).recorded_at = "2026-08-13T11:33:00Z";
        }
      });
    }],
    ["baseline after disable", (input) => {
      const run = evidenceByKind(input, "GITHUB_RUN", "legacy-baseline");
      const revision = evidenceByKind(input, "CLOUD_RUN_REVISION", "legacy-baseline-revision");
      run.data.started_at = "2026-08-13T12:10:01Z";
      run.observed_at = "2026-08-13T12:11:00Z";
      revision.data.create_time = "2026-08-13T12:10:02Z";
      revision.observed_at = "2026-08-13T12:11:00Z";
      refreshCheckpointReceipt(input);
      mutateCheckpointReceipt(input, (receipt) => {
        for (const id of [run.id, revision.id]) {
          receipt.evidence.find((record) => record.id === id).recorded_at = "2026-08-13T12:10:03Z";
        }
      });
    }],
  ];
  for (const [label, mutate] of attacks) {
    const input = validK0BundleInput();
    mutate(input);
    await assert.rejects(() => assembleK0Bundle(input), undefined, label);
  }
});

test("coherent active-WIF workflow substitution cannot satisfy the legacy baseline pin", async () => {
  const input = validK0BundleInput();
  const activeBytes = await readFile(new URL("../k0/templates/k0-deploy.wif.yml", import.meta.url));
  const activeBlobSha = createHash("sha1")
    .update(Buffer.from(`blob ${activeBytes.length}\0`)).update(activeBytes).digest("hex");
  const activeSha256 = createHash("sha256").update(activeBytes).digest("hex");
  input.manifest.approved_workflows.baseline.workflow_blob_sha = activeBlobSha;
  input.manifest.approved_workflows.baseline.workflow_sha256 = activeSha256;
  const approval = evidenceByKind(input, "GITHUB_PULL_REQUEST", "baseline-workflow-approval").data;
  approval.workflow_blob_sha = activeBlobSha;
  approval.workflow_sha256 = activeSha256;
  const run = evidenceByKind(input, "GITHUB_RUN", "legacy-baseline").data;
  run.workflow_blob_sha = activeBlobSha;
  run.workflow_sha256 = activeSha256;
  refreshCheckpointReceipt(input);
  const candidate = preDisableCandidate(input);
  assert.equal((await verifyK0PreDisableEvidenceSemantics(
    candidate.fragment,
    candidate.evidence,
    async (id) => candidate.artifacts.get(id),
  )).ok, false);
  await assert.rejects(() => assembleK0Bundle(input), /legacy baseline approved workflow bytes do not match the inactive fixture/);
});

test("checkpoint binds protected review, receipt bytes, push run, and required check", async () => {
  const attacks = [
    ["protection", (checkpoint) => { checkpoint.protection.require_last_push_approval = false; }],
    ["linear history false", (checkpoint) => { checkpoint.protection.required_linear_history = false; }],
    ["linear history missing", (checkpoint) => { delete checkpoint.protection.required_linear_history; }],
    ["review", (checkpoint) => { checkpoint.pull.reviewer_id = checkpoint.pull.author_id; }],
    ["head", (checkpoint) => { checkpoint.pull.review_commit_sha = "d".repeat(40); }],
    ["merge", (checkpoint) => { checkpoint.run.head_sha = "d".repeat(40); }],
    ["blob", (checkpoint) => { checkpoint.receipt.blob_sha = "d".repeat(40); }],
    ["content", (checkpoint) => { checkpoint.receipt.bytes_base64 = Buffer.from("{}\n").toString("base64"); }],
    ["archive path", (checkpoint) => { checkpoint.archive.path = checkpoint.receipt.path; }],
    ["archive blob", (checkpoint) => { checkpoint.archive.blob_sha = "not-a-sha"; }],
    ["archive digest", (checkpoint) => { checkpoint.archive.ledger_sha256 = "0"; }],
    ["archive seal", (checkpoint) => { checkpoint.archive.sealed_at = checkpoint.pull.merged_at; }],
    ["check", (checkpoint) => { checkpoint.check.name = "not-test"; }],
    ["app", (checkpoint) => { checkpoint.check.app_id = "1"; }],
    ["time", (checkpoint) => { checkpoint.check.completed_at = "2026-08-13T12:10:01Z"; }],
    ["run completion", (checkpoint) => { checkpoint.run.completed_at = "2026-08-13T12:10:01Z"; }],
  ];
  for (const [label, mutate] of attacks) {
    const input = validK0BundleInput();
    mutate(evidenceByKind(input, "GITHUB_EVIDENCE_CHECKPOINT").data);
    await assert.rejects(() => assembleK0Bundle(input), undefined, label);
  }
});

test("checkpoint semantics reject noncanonical receipt and archive path substitutions", async () => {
  const invalidPaths = [
    "docs/evidence/../bad.json",
    "docs/evidence/./bad.json",
    "docs/evidence//bad.json",
    "docs/evidence/bad.json/",
    "/docs/evidence/bad.json",
    "docs\\evidence\\bad.json",
    "docs/evidence/%2e%2e/bad.json",
    "docs/evidence/bad.json?raw=1",
    "docs/evidence/bad.json#fragment",
    "docs/evidence/bad\u0000.json",
    "docs/ｅvidence/bad.json",
    `docs/evidence/${"a".repeat(247)}.json`,
  ];
  for (const field of ["receipt", "archive"]) {
    for (const path of invalidPaths) {
      const input = validK0BundleInput();
      evidenceByKind(input, "GITHUB_EVIDENCE_CHECKPOINT").data[field].path = path;
      await assert.rejects(() => assembleK0Bundle(input), undefined, `${field}: ${JSON.stringify(path)}`);
    }
  }
});

test("manifest pins distinct forbidden observations and exact source sets", async () => {
  const bundle = await assembleK0Bundle(validK0BundleInput());
  for (const mutate of [
    (manifest) => { manifest.revisions.forbidden_after_source_id = manifest.revisions.forbidden_before_source_id; },
    (manifest) => { manifest.hostile_tests[7].source_ids.pop(); },
    (manifest) => { manifest.post_disable.source_ids.push(manifest.leak_scan.source_ids[0]); },
    (manifest) => { manifest.post_disable.run_attempt = "2"; },
    (manifest) => { manifest.scope.project_number = "999"; },
  ]) {
    const changed = structuredClone(bundle.manifest);
    mutate(changed);
    await assert.rejects(() => verifyK0Bundle({ manifest: changed, artifacts: bundle.artifacts }));
  }
});

test("full semantics independently recompute the exact final credential scan", async () => {
  const valid = await assembleK0Bundle(validK0BundleInput());
  const scanId = valid.manifest.leak_scan.source_ids[0];
  const expected = createCredentialScan(valid.manifest.scope, new Map(
    valid.manifest.evidence
      .filter(({ kind }) => kind !== "LEAK_SCAN")
      .map(({ id }) => [id, Buffer.from(valid.artifacts.get(id))]),
  ));
  assert.deepEqual(JSON.parse(valid.artifacts.get(scanId)).data, expected);

  const omitted = await assembleK0Bundle(validK0BundleInput());
  omitted.manifest.evidence = omitted.manifest.evidence.filter(({ id }) => id !== scanId);
  omitted.artifacts.delete(scanId);
  assert.equal((await semanticResult(omitted)).ok, false);

  const duplicated = await assembleK0Bundle(validK0BundleInput());
  const duplicateEnvelope = JSON.parse(duplicated.artifacts.get(scanId));
  duplicateEnvelope.id = "E099";
  duplicateEnvelope.locator = "credential-scan:duplicate";
  const duplicate = createEvidenceArtifact(duplicateEnvelope);
  duplicated.artifacts.set("E099", Buffer.from(duplicate.artifact));
  duplicated.manifest.evidence.push({
    id: "E099",
    kind: "LEAK_SCAN",
    locator: duplicateEnvelope.locator,
    observed_at: duplicateEnvelope.observed_at,
    sha256: duplicate.sha256,
  });
  duplicated.manifest.evidence.sort((left, right) => left.id.localeCompare(right.id));
  assert.equal((await semanticResult(duplicated)).ok, false);

  for (const mutate of [
    (data) => { data.artifact_count += 1; },
    (data) => { data.scope_hash = "0".repeat(64); },
    (data) => { data.scanner = "KEYLESS_CREDENTIAL_SCAN_V0"; },
  ]) {
    const changed = await assembleK0Bundle(validK0BundleInput());
    replaceArtifact(changed, scanId, ({ data }) => mutate(data));
    const result = await semanticResult(changed);
    assert.equal(result.ok, false);
    assert.equal(result.errors.some((error) => error.includes("final credential scan body")), true);
  }

  const stale = await assembleK0Bundle(validK0BundleInput());
  const postAuthId = stale.manifest.legacy_after_disable.source_ids.find(
    (id) => stale.manifest.evidence.find((entry) => entry.id === id)?.kind === "GOOGLE_AUTH_RESULT",
  );
  replaceArtifact(stale, postAuthId, ({ data }) => { data.log_sha256 = "8".repeat(64); });
  const staleResult = await semanticResult(stale);
  assert.equal(staleResult.ok, false);
  assert.equal(staleResult.errors.includes("final credential scan body does not match every non-scan artifact"), true);

  for (const locator of [
    "credential-scan:predisable-archive",
    "credential-scan",
    "credential-scan:final",
    "Credential-scan:final-bundle",
    "credential-scan:final-bundle-near",
  ]) {
    const wrongLocator = await assembleK0Bundle(validK0BundleInput());
    replaceArtifact(wrongLocator, scanId, (envelope) => { envelope.locator = locator; });
    const locatorResult = await semanticResult(wrongLocator);
    assert.equal(locatorResult.ok, false);
    assert.equal(locatorResult.errors.includes("final credential scan locator is invalid"), true);
  }

  const credential = await assembleK0Bundle(validK0BundleInput());
  const credentialText = `gh${"p"}_${"z".repeat(24)}`;
  const encodedCredential = Buffer.from(credentialText).toString("base64");
  replaceArtifact(credential, postAuthId, (envelope) => { envelope.locator = encodedCredential; });
  const credentialResult = await semanticResult(credential);
  assert.equal(credentialResult.ok, false);
  assert.equal(credentialResult.errors.includes("final credential scan did not verify every non-scan artifact"), true);
  assert.equal(credentialResult.errors.join(" ").includes(credentialText), false);
  assert.equal(credentialResult.errors.join(" ").includes(encodedCredential), false);
});

test("semantic verification snapshots every artifact exactly once", async () => {
  const input = validK0BundleInput();
  const bundle = await assembleK0Bundle(input);
  const target = evidenceByKind(input, "GOOGLE_AUTH_RESULT");
  target.data.key_id = "b".repeat(40);
  const changed = createEvidenceArtifact(target);
  const manifest = structuredClone(bundle.manifest);
  manifest.evidence.find(({ id }) => id === target.id).sha256 = changed.sha256;
  const calls = new Map();
  const result = await verifyK0EvidenceSemantics(manifest, async (id) => {
    calls.set(id, (calls.get(id) ?? 0) + 1);
    return id === target.id && calls.get(id) === 1 ? changed.artifact : bundle.artifacts.get(id);
  });
  assert.equal(result.ok, false);
  assert.equal([...calls.values()].every((count) => count === 1), true);
});

test("bundle verification rejects artifact bytes outside the manifest ledger", async () => {
  const bundle = await assembleK0Bundle(validK0BundleInput());
  const extra = new Map(bundle.artifacts);
  extra.set("E099", Buffer.from("{}\n"));
  await assert.rejects(() => verifyK0Bundle({ manifest: bundle.manifest, artifacts: extra }), /exactly match/);

  const first = bundle.manifest.evidence[0];
  const changed = Buffer.from(bundle.artifacts.get(first.id));
  changed[changed.length - 2] ^= 1;
  const digest = createHash("sha256").update(changed).digest("hex");
  assert.notEqual(digest, first.sha256);
});

test("release markers for legacy baseline, wif-1, and wif-2 must be pairwise distinct", async () => {
  const collideBaselineWif1 = validK0BundleInput();
  collideBaselineWif1.manifest.legacy_baseline.release_marker = collideBaselineWif1.manifest.cutover.wif_1_release_marker;
  collideBaselineWif1.manifest.revisions.legacy_1 = `keyless-demo-${collideBaselineWif1.manifest.legacy_baseline.release_marker}`;
  evidenceByKind(collideBaselineWif1, "GITHUB_RUN", "legacy-baseline").data.release_marker =
    collideBaselineWif1.manifest.legacy_baseline.release_marker;
  evidenceByKind(collideBaselineWif1, "CLOUD_RUN_REVISION", "legacy-baseline-revision").data.release_marker =
    collideBaselineWif1.manifest.legacy_baseline.release_marker;
  evidenceByKind(collideBaselineWif1, "CLOUD_RUN_REVISION", "legacy-baseline-revision").data.revision =
    collideBaselineWif1.manifest.revisions.legacy_1;
  refreshCheckpointReceipt(collideBaselineWif1);
  refreshFinalCredentialScan(collideBaselineWif1);
  await assert.rejects(
    () => assembleK0Bundle(collideBaselineWif1),
    /legacy baseline and wif-1 release markers must be distinct/,
  );

  const collidePostWif1 = validK0BundleInput();
  collidePostWif1.manifest.post_disable.release_marker = collidePostWif1.manifest.cutover.wif_1_release_marker;
  collidePostWif1.manifest.revisions.wif_2 = `keyless-demo-${collidePostWif1.manifest.post_disable.release_marker}`;
  evidenceByKind(collidePostWif1, "GITHUB_RUN", "wif-2").data.release_marker =
    collidePostWif1.manifest.post_disable.release_marker;
  evidenceByKind(collidePostWif1, "CLOUD_RUN_REVISION", "wif-2-revision").data.release_marker =
    collidePostWif1.manifest.post_disable.release_marker;
  evidenceByKind(collidePostWif1, "CLOUD_RUN_REVISION", "wif-2-revision").data.revision =
    collidePostWif1.manifest.revisions.wif_2;
  refreshFinalCredentialScan(collidePostWif1);
  await assert.rejects(
    () => assembleK0Bundle(collidePostWif1),
    /post-disable release marker must be distinct/,
  );

  const collidePostBaseline = validK0BundleInput();
  collidePostBaseline.manifest.post_disable.release_marker =
    collidePostBaseline.manifest.legacy_baseline.release_marker;
  collidePostBaseline.manifest.revisions.wif_2 =
    `keyless-demo-${collidePostBaseline.manifest.post_disable.release_marker}`;
  evidenceByKind(collidePostBaseline, "GITHUB_RUN", "wif-2").data.release_marker =
    collidePostBaseline.manifest.post_disable.release_marker;
  evidenceByKind(collidePostBaseline, "CLOUD_RUN_REVISION", "wif-2-revision").data.release_marker =
    collidePostBaseline.manifest.post_disable.release_marker;
  evidenceByKind(collidePostBaseline, "CLOUD_RUN_REVISION", "wif-2-revision").data.revision =
    collidePostBaseline.manifest.revisions.wif_2;
  refreshFinalCredentialScan(collidePostBaseline);
  await assert.rejects(
    () => assembleK0Bundle(collidePostBaseline),
    /post-disable release marker must be distinct/,
  );
});
