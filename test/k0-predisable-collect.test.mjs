import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import AdmZip from "adm-zip";

import { canonicalJson, createEvidenceArtifact } from "../src/evidence-artifact.mjs";
import { FirestoreChallengeStore } from "../src/firestore-challenge-store.mjs";
import { createKeyProof, expectedKeyProofContext } from "../src/key-proof.mjs";
import { parseGitHubEvidenceCheckpointReceipt } from "../src/k0-evidence-normalizer.mjs";
import { verifyK0PreDisableEvidenceSemantics } from "../src/k0-evidence-semantics.mjs";
import { collectK0PreDisable, observeK0ForbiddenBefore } from "../src/k0-predisable-collect.mjs";
import {
  createK0PreDisableArchive,
  parseK0PreDisableArchivePlanBytes,
  verifyK0PreDisableArchive,
} from "../src/k0-predisable-archive.mjs";
import { issueProofV2, verifyAndConsumeProofV2 } from "../src/proofv2-operator.mjs";
import { buildWifPlan } from "../src/wif-plan.mjs";

class MemoryFirestore {
  documents = new Map();
  updates = new Map();
  tail = Promise.resolve();
  constructor(clock) {
    this.clock = clock;
  }
  collection() {
    return { doc: (id) => ({
      id,
      create: async (value) => {
        this.documents.set(id, structuredClone(value));
        this.updates.set(id, this.clock());
      },
      get: async () => this.snapshot(id),
    }) };
  }
  snapshot(id) {
    const value = this.documents.get(id);
    return {
      exists: value !== undefined,
      data: () => structuredClone(value),
      updateTime: this.updates.get(id),
      readTime: new Date("2026-08-13T11:33:00Z"),
    };
  }
  async runTransaction(callback) {
    let release;
    const previous = this.tail;
    this.tail = new Promise((resolve) => { release = resolve; });
    await previous;
    const patches = [];
    try {
      const result = await callback({
        get: async (reference) => this.snapshot(reference.id),
        update: (reference, patch) => patches.push([reference.id, patch]),
      });
      for (const [id, patch] of patches) {
        this.documents.set(id, { ...this.documents.get(id), ...patch });
        this.updates.set(id, this.clock());
      }
      return result;
    } finally {
      release();
    }
  }
}

const installationToken = `ghs_${"t".repeat(36)}`;
const keyId = "a".repeat(40);
const owner = "trustphoneapp";
const repository = "keyless-cutover";
const scope = {
  owner_id: "1",
  repository_id: "2",
  workflow_path: ".github/workflows/k0-deploy.yml",
  proof_workflow_path: ".github/workflows/k0-proof-v2.yml",
  legacy_workflow_path: ".github/workflows/k0-legacy-auth-check.yml",
  h1_workflow_path: ".github/workflows/k0-deploy.yml",
  h2_workflow_path: ".github/workflows/k0-external-hostile.yml",
  h4_workflow_path: ".github/workflows/k0-hostile-wrong-workflow.yml",
  project_id: "keyless-k0-demo",
  project_number: "3",
  region: "us-central1",
  service_account_email: "keyless-deploy@keyless-k0-demo.iam.gserviceaccount.com",
  service_account_unique_id: "110652672782847439596",
  key_id: keyId,
  allowed_service: "keyless-demo",
  forbidden_service: "keyless-forbidden",
};
const wifPlan = buildWifPlan({
  project_id: scope.project_id,
  project_number: scope.project_number,
  pool_id: "keyless-k0",
  provider_id: "github",
  owner_id: scope.owner_id,
  repository_id: scope.repository_id,
  owner,
  repository,
  service_account: scope.service_account_email,
});
const repositories = {
  [`${owner}/${repository}`]: { owner_id: 1, repository_id: 2 },
  "cherala2002/keyless-h1-probe": { owner_id: 999, repository_id: 998 },
  [`${owner}/keyless-hostile`]: { owner_id: 1, repository_id: 997 },
};
const heads = {
  baselinePull: "0".repeat(40),
  baselineRun: "d".repeat(40),
  cutoverPull: "8".repeat(40),
  cutoverMerge: "9".repeat(40),
  proof: "7".repeat(40),
  hostile: "f".repeat(40),
};
const legacyTemplate = await readFile(new URL("../k0/templates/k0-deploy.legacy.yml", import.meta.url));
const cutoverWorkflow = Buffer.from("name: K0 deploy\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    environment: production\n");
const proofWorkflow = Buffer.from("name: K0 ProofV2\njobs:\n  proof:\n    runs-on: ubuntu-latest\n    environment: production\n");
const hostileJobs = {
  H1: "external-identity",
  H2: "external-identity",
  H3: "h3-wrong-ref",
  H4: "hostile",
  H5: "h5-wrong-event",
  H6: "h6-wrong-environment",
  H7: "h7-wrong-audience",
  H8: "h8-forbidden-resource",
};
const hostileRepositories = {
  H1: "cherala2002/keyless-h1-probe",
  H2: `${owner}/keyless-hostile`,
};
const hostilePaths = {
  H1: scope.h1_workflow_path,
  H2: scope.h2_workflow_path,
  H4: scope.h4_workflow_path,
};
const conditionLog = `federated token for //iam.googleapis.com/${wifPlan.provider}: credential is rejected by the attribute condition, google-github-actions/auth failed`;
const hostileLogs = {
  H7: `federated token for //iam.googleapis.com/${wifPlan.provider}: allowed audiences rejected an invalid audience, google-github-actions/auth failed`,
  H8: "PERMISSION_DENIED: the caller does not have permission for run.services.update on Cloud Run",
};

function blobSha(bytes) {
  return createHash("sha1").update(Buffer.from(`blob ${bytes.length}\0`)).update(bytes).digest("hex");
}

function contents(bytes) {
  return { encoding: "base64", content: bytes.toString("base64"), sha: blobSha(bytes) };
}

function httpDate(iso) {
  return new Date(iso).toUTCString();
}

function reply(value, iso, status = 200) {
  const bytes = Buffer.isBuffer(value) ? value
    : Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
  return new Response(bytes, { status, headers: { date: httpDate(iso) } });
}

function redirect(location, iso) {
  return new Response(Buffer.alloc(0), { status: 302, headers: { date: httpDate(iso), location } });
}

function workflowBytes(fullName, path, ref) {
  if (path === "demo/release.txt") {
    if (fullName !== `${owner}/${repository}`) return Buffer.from("external\n");
    return Buffer.from(ref === heads.baselineRun ? "legacy-1\n" : "wif-1\n");
  }
  if (fullName === `${owner}/${repository}` && path === scope.workflow_path) {
    return [heads.baselinePull, heads.baselineRun].includes(ref) ? legacyTemplate : cutoverWorkflow;
  }
  if (fullName === `${owner}/${repository}` && path === scope.proof_workflow_path) return proofWorkflow;
  return Buffer.from(`name: ${fullName} ${path}\n`);
}

function pullRequest({ number, fullName, head, merge, reviewedAt, mergedAt }) {
  const identity = repositories[fullName];
  return {
    pull: {
      number,
      state: "closed",
      merged: true,
      merged_at: mergedAt,
      merge_commit_sha: merge,
      head: { sha: head },
      user: { id: 20 },
      base: { ref: "main", repo: { id: identity.repository_id, full_name: fullName, owner: { id: identity.owner_id } } },
    },
    reviews: [{ state: "APPROVED", commit_id: head, submitted_at: reviewedAt, user: { id: 21 } }],
  };
}

const pulls = {
  [`${owner}/${repository}`]: {
    6: pullRequest({
      number: 6, fullName: `${owner}/${repository}`, head: heads.baselinePull, merge: "a".repeat(40),
      reviewedAt: "2026-08-13T10:43:00Z", mergedAt: "2026-08-13T10:44:00Z",
    }),
    9: pullRequest({
      number: 9, fullName: `${owner}/${repository}`, head: "2".repeat(40), merge: "6".repeat(40),
      reviewedAt: "2026-08-13T10:53:00Z", mergedAt: "2026-08-13T10:54:00Z",
    }),
    10: pullRequest({
      number: 10, fullName: `${owner}/${repository}`, head: "3".repeat(40), merge: "7".repeat(40),
      reviewedAt: "2026-08-13T10:53:00Z", mergedAt: "2026-08-13T10:54:00Z",
    }),
    11: pullRequest({
      number: 11, fullName: `${owner}/${repository}`, head: heads.cutoverPull, merge: heads.cutoverMerge,
      reviewedAt: "2026-08-13T10:56:00Z", mergedAt: "2026-08-13T10:57:00Z",
    }),
  },
  "cherala2002/keyless-h1-probe": {
    7: pullRequest({
      number: 7, fullName: "cherala2002/keyless-h1-probe", head: "1".repeat(40), merge: "4".repeat(40),
      reviewedAt: "2026-08-13T10:53:00Z", mergedAt: "2026-08-13T10:54:00Z",
    }),
  },
  [`${owner}/keyless-hostile`]: {
    8: pullRequest({
      number: 8, fullName: `${owner}/keyless-hostile`, head: "4".repeat(40), merge: "5".repeat(40),
      reviewedAt: "2026-08-13T10:53:00Z", mergedAt: "2026-08-13T10:54:00Z",
    }),
  },
};
const protection = {
  required_status_checks: { strict: true, checks: [{ context: "test", app_id: 15368 }] },
  required_pull_request_reviews: {
    required_approving_review_count: 1, dismiss_stale_reviews: true, require_last_push_approval: true,
  },
  enforce_admins: { enabled: true },
  required_linear_history: { enabled: true },
};

function hostileArtifact(id, run, ref) {
  const value = {
    version: 1,
    id: ["H1", "H2"].includes(id) ? "external" : id,
    outcome: "failure",
    run_id: String(run.id),
    run_attempt: String(run.run_attempt),
    head_sha: run.head_sha,
    event: run.event,
    ref,
    environment: id === "H6" ? "staging" : "production",
    workflow_ref: `${run.repository.full_name}/${run.path}@${ref}`,
  };
  if (id === "H1") return { ...value, owner_id: "999", repository_id: "998" };
  if (id === "H2") return { ...value, owner_id: "1", repository_id: "997" };
  if (id === "H7") return { ...value, audience: `https://iam.googleapis.com/projects/0/locations/global/workloadIdentityPools/keyless-k0/providers/github` };
  if (id === "H8") return { ...value, target: scope.forbidden_service };
  return value;
}

function hostileRun(id, index) {
  const fullName = hostileRepositories[id] ?? `${owner}/${repository}`;
  const identity = repositories[fullName];
  const run = {
    id: 2000 + index,
    run_attempt: 1,
    status: "completed",
    conclusion: "success",
    head_sha: heads.hostile,
    head_branch: id === "H3" ? "keyless-h3" : "main",
    path: hostilePaths[id] ?? scope.workflow_path,
    event: id === "H5" ? "workflow_dispatch" : "push",
    run_started_at: "2026-08-13T11:45:00Z",
    actor: { id: 10 },
    repository: { id: identity.repository_id, full_name: fullName, owner: { id: identity.owner_id } },
  };
  const ref = `refs/heads/${run.head_branch}`;
  const zip = new AdmZip();
  zip.addFile(
    ["H1", "H2"].includes(id) ? "k0-external.json" : `k0-${id}.json`,
    Buffer.from(JSON.stringify(hostileArtifact(id, run, ref))),
  );
  return {
    run,
    jobId: 3000 + index,
    artifactId: 4000 + index,
    artifactName: ["H1", "H2"].includes(id) ? "keyless-external-denial" : `keyless-${id.toLowerCase()}-denial`,
    stepName: `Require ${["H1", "H2"].includes(id) ? "external identity" : id} denial`,
    jobName: hostileJobs[id],
    zip: zip.toBuffer(),
    log: hostileLogs[id] ?? conditionLog,
  };
}

const hostileFixtures = Object.fromEntries(
  ["H1", "H2", "H3", "H4", "H5", "H6", "H7", "H8"].map((id, index) => [id, hostileRun(id, index + 1)]),
);

const baselineRun = {
  id: 1401,
  run_attempt: 1,
  status: "completed",
  conclusion: "success",
  head_sha: heads.baselineRun,
  head_branch: "main",
  path: scope.workflow_path,
  event: "workflow_dispatch",
  run_started_at: "2026-08-13T10:46:00Z",
  updated_at: "2026-08-13T10:48:00Z",
  actor: { id: 10 },
  repository: { id: 2, full_name: `${owner}/${repository}`, owner: { id: 1 } },
};
const wif1Run = {
  id: 1501,
  run_attempt: 1,
  status: "completed",
  conclusion: "success",
  head_sha: heads.cutoverMerge,
  head_branch: "main",
  path: scope.workflow_path,
  event: "push",
  run_started_at: "2026-08-13T11:35:00Z",
  actor: { id: 10 },
  repository: { id: 2, full_name: `${owner}/${repository}`, owner: { id: 1 } },
};
const proofRun = {
  id: 1001,
  run_attempt: 1,
  status: "completed",
  conclusion: "success",
  head_sha: heads.proof,
  head_branch: "main",
  path: scope.proof_workflow_path,
  event: "workflow_dispatch",
  run_started_at: "2026-08-13T11:30:00Z",
  actor: { id: 10 },
  triggering_actor: { login: owner },
  repository: { id: 2, full_name: `${owner}/${repository}`, owner: { id: 1 } },
};
const runs = {
  1401: {
    run: baselineRun,
    date: "2026-08-13T10:48:00Z",
    jobs: { total_count: 1, jobs: [{
      id: 1411, name: "deploy", status: "completed", conclusion: "success",
      runner_group_name: "GitHub Actions", labels: ["ubuntu-latest"],
      started_at: "2026-08-13T10:46:05Z", completed_at: "2026-08-13T10:47:30Z",
      steps: [
        { name: "Read the reviewed release marker", conclusion: "success" },
        { name: "Authenticate with the legacy key", conclusion: "success" },
        { name: "Deploy through the legacy key", conclusion: "success" },
      ],
    }] },
    approvals: [{ state: "approved", user: { id: 11 }, environments: [{ name: "production" }] }],
  },
  1001: {
    run: proofRun,
    date: "2026-08-13T11:33:00Z",
    jobs: { total_count: 1, jobs: [{
      id: 1101, name: "proof", status: "completed", conclusion: "success",
      runner_group_name: "GitHub Actions", labels: ["ubuntu-latest"],
    }] },
    approvals: [{ state: "approved", user: { id: 11, login: "cherala2002" }, environments: [{ name: "production" }] }],
  },
  1501: {
    run: wif1Run,
    date: "2026-08-13T11:39:00Z",
    jobs: { total_count: 1, jobs: [{
      id: 1601, name: "deploy", status: "completed", conclusion: "success",
      runner_group_name: "GitHub Actions", labels: ["ubuntu-latest"],
      started_at: "2026-08-13T11:36:00Z", completed_at: "2026-08-13T11:37:00Z",
      steps: [
        { name: "Authenticate through WIF", conclusion: "success" },
        { name: "Deploy through WIF", conclusion: "success" },
      ],
    }] },
    approvals: [{ state: "approved", user: { id: 11 }, environments: [{ name: "production" }] }],
  },
};
for (const fixture of Object.values(hostileFixtures)) {
  runs[fixture.run.id] = {
    run: fixture.run,
    date: "2026-08-13T11:52:00Z",
    jobs: { total_count: 1, jobs: [{
      id: fixture.jobId, name: fixture.jobName, status: "completed", conclusion: "success",
      runner_group_name: "GitHub Actions", labels: ["ubuntu-latest"],
      started_at: "2026-08-13T11:46:00Z", completed_at: "2026-08-13T11:50:00Z",
      steps: [{ name: fixture.stepName, conclusion: "success" }],
    }] },
    artifacts: { total_count: 1, artifacts: [{ id: fixture.artifactId, name: fixture.artifactName, expired: false }] },
    downloads: fixture,
  };
}

const provider = {
  name: wifPlan.provider,
  state: "ACTIVE",
  oidc: { issuerUri: wifPlan.issuer, allowedAudiences: [] },
  attributeMapping: wifPlan.attribute_mapping,
  attributeCondition: wifPlan.attribute_condition,
};
const serviceAccountPolicy = {
  version: 1,
  etag: "service-etag-1",
  bindings: [
    { role: wifPlan.impersonation_binding.role, members: [wifPlan.impersonation_binding.member] },
    { role: "roles/iam.serviceAccountAdmin", members: ["user:key-operator@example.com"] },
  ],
};
const allowedPolicy = {
  version: 1,
  etag: "allowed-etag-1",
  bindings: [{ role: "roles/run.developer", members: [`serviceAccount:${scope.service_account_email}`] }],
};
const forbiddenPolicy = { version: 1, etag: "forbidden-etag-1", bindings: [] };
const serviceAccount = {
  name: `projects/${scope.project_id}/serviceAccounts/${scope.service_account_email}`,
  projectId: scope.project_id,
  email: scope.service_account_email,
  uniqueId: scope.service_account_unique_id,
};
const forbiddenTarget = {
  revision: "forbidden-00001",
  release_marker: "stable",
  create_time: "2026-08-12T10:00:00Z",
  image_digest: `sha256:${"b".repeat(64)}`,
};

function revisionBody(service, revision, marker, createTime, digest) {
  return {
    name: `projects/${scope.project_id}/locations/${scope.region}/services/${service}/revisions/${revision}`,
    createTime,
    conditions: [{ type: "Ready", state: "CONDITION_SUCCEEDED" }],
    containers: [{
      image: `us-docker.pkg.dev/example/app@${digest}`,
      env: [{ name: "RELEASE", value: marker }],
    }],
  };
}

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const serviceAccountKey = JSON.stringify({
  type: "service_account",
  client_email: scope.service_account_email,
  private_key_id: keyId,
  private_key: privateKey.export({ type: "pkcs8", format: "pem" }),
});
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
const googleKey = {
  name: `projects/-/serviceAccounts/${scope.service_account_email}/keys/${keyId}`,
  keyType: "USER_MANAGED",
  keyAlgorithm: "KEY_ALG_RSA_2048",
  disabled: false,
  validAfterTime: "2026-08-01T00:00:00Z",
};

async function consumedProofReceipt() {
  let clock = new Date("2026-08-13T11:29:00Z");
  const store = new FirestoreChallengeStore({
    firestore: new MemoryFirestore(() => clock),
    now: () => clock,
  });
  const { challenge } = await issueProofV2({
    challengeStore: store,
    scope: {
      migration_id: "k0-predisable-collect",
      owner_id: scope.owner_id,
      repository_id: scope.repository_id,
      workflow_path: scope.proof_workflow_path,
      event_name: "workflow_dispatch",
      ref: "refs/heads/main",
      environment: "production",
      client_email: scope.service_account_email,
    },
  });
  const observed = {
    owner_id: scope.owner_id,
    repository_id: scope.repository_id,
    workflow_path: scope.proof_workflow_path,
    workflow_ref: `${owner}/${repository}/${scope.proof_workflow_path}@refs/heads/main`,
    workflow_blob_sha: blobSha(proofWorkflow),
    head_sha: heads.proof,
    run_id: "1001",
    run_attempt: "1",
    actor_id: "10",
    triggering_actor: owner,
    event_name: "workflow_dispatch",
    ref: "refs/heads/main",
    environment: "production",
    runner_environment: "github-hosted",
    started_at: proofRun.run_started_at,
  };
  const proof = createKeyProof(serviceAccountKey, expectedKeyProofContext(challenge, observed, keyId));
  clock = new Date("2026-08-13T11:32:00Z");
  const receipt = await verifyAndConsumeProofV2({
    challengeStore: store,
    proof,
    observed,
    getGoogleKey: async () => googleKey,
    fetchImpl: async () => reply({ [keyId]: publicKeyPem }, "2026-08-13T11:32:00Z"),
    now: clock,
  });
  return { store, proof, receiptBytes: Buffer.from(canonicalJson(receipt)) };
}

function fetchHarness(proof) {
  const zip = new AdmZip();
  zip.addFile("keyless-proof-v2.json", Buffer.from(JSON.stringify(proof)));
  const proofZip = zip.toBuffer();
  const parityDates = Array.from({ length: 9 }, (_, index) => `2026-08-13T11:42:0${index}Z`);
  let parityIndex = 0;
  let forbiddenIndex = 0;
  const parityDate = () => parityDates[parityIndex++] ?? "2026-08-13T11:42:09Z";
  return async (url, options = {}) => {
    const github = /^https:\/\/api\.github\.com\/repos\/([^/]+)\/([^/]+)\/(.+)$/.exec(url);
    if (github) {
      const fullName = `${github[1]}/${github[2]}`;
      const rest = github[3];
      const runMatch = /^actions\/runs\/(\d+)(\/[a-z]+)?/.exec(rest);
      if (runMatch) {
        const record = runs[runMatch[1]];
        if (!record) throw new Error(`unexpected run ${url}`);
        if (!runMatch[2]) return reply(record.run, record.date);
        if (runMatch[2] === "/jobs") return reply(record.jobs, record.date);
        if (runMatch[2] === "/approvals") return reply(record.approvals, record.date);
        if (runMatch[2] === "/artifacts") {
          if (record.artifacts) return reply(record.artifacts, record.date);
          return reply({ total_count: 1, artifacts: [{ id: 1201, name: "keyless-proof-v2-1001-1", expired: false }] },
            record.date);
        }
      }
      const artifactMatch = /^actions\/artifacts\/(\d+)\/zip$/.exec(rest);
      if (artifactMatch) {
        return redirect(`https://objects.githubusercontent.com/artifact-${artifactMatch[1]}.zip`, "2026-08-13T11:52:00Z");
      }
      const logMatch = /^actions\/jobs\/(\d+)\/logs$/.exec(rest);
      if (logMatch) {
        return redirect(`https://objects.githubusercontent.com/job-${logMatch[1]}.txt`, "2026-08-13T11:52:00Z");
      }
      const pullMatch = /^pulls\/(\d+)(\/reviews)?/.exec(rest);
      if (pullMatch) {
        const record = pulls[fullName]?.[pullMatch[1]];
        if (!record) throw new Error(`unexpected pull ${url}`);
        return reply(pullMatch[2] ? record.reviews : record.pull, "2026-08-13T10:48:00Z");
      }
      if (rest === "branches/main/protection") return reply(protection, "2026-08-13T10:48:00Z");
      const contentMatch = /^contents\/(.+)\?ref=([a-f0-9]{40})$/.exec(rest);
      if (contentMatch) {
        const path = decodeURIComponent(contentMatch[1]);
        return reply(contents(workflowBytes(fullName, path, contentMatch[2])), "2026-08-13T11:52:00Z");
      }
    }
    const download = /^https:\/\/objects\.githubusercontent\.com\/(artifact|job)-(\d+)\.(zip|txt)$/.exec(url);
    if (download) {
      const id = Number(download[2]);
      if (id === 1201) return reply(proofZip, "2026-08-13T11:33:00Z");
      const fixture = Object.values(hostileFixtures)
        .find((value) => value.artifactId === id || value.jobId === id);
      if (!fixture) throw new Error(`unexpected download ${url}`);
      return reply(download[1] === "artifact" ? fixture.zip : fixture.log, "2026-08-13T11:52:00Z");
    }
    if (url.startsWith("https://www.googleapis.com/robot/v1/metadata/x509/")) {
      return reply({ [keyId]: publicKeyPem }, "2026-08-13T11:33:00Z");
    }
    if (url.includes("/keys/")) return reply(googleKey, "2026-08-13T10:52:00Z");
    if (url.includes("workloadIdentityPools") && url.startsWith("https://iam.googleapis.com/")) {
      return reply(provider, parityDate());
    }
    if (url.startsWith("https://iam.googleapis.com/")) {
      if (url.endsWith(":getIamPolicy")) return reply(serviceAccountPolicy, parityDate());
      return reply(serviceAccount, parityDate());
    }
    if (url.startsWith("https://run.googleapis.com/") && url.includes(":getIamPolicy")) {
      return reply(url.includes(scope.forbidden_service) ? forbiddenPolicy : allowedPolicy, parityDate());
    }
    const revision = /\/services\/([a-z0-9-]+)\/revisions\/([a-z0-9-]+)$/.exec(url);
    if (revision && options.method === "GET") {
      if (revision[2] === forbiddenTarget.revision) {
        forbiddenIndex += 1;
        return reply(
          revisionBody(revision[1], revision[2], forbiddenTarget.release_marker,
            forbiddenTarget.create_time, forbiddenTarget.image_digest),
          forbiddenIndex === 1 ? "2026-08-13T10:40:00Z" : "2026-08-13T12:00:00Z",
        );
      }
      if (revision[2] === "keyless-demo-legacy-1") {
        return reply(
          revisionBody(revision[1], revision[2], "legacy-1", "2026-08-13T10:47:00Z", `sha256:${"c".repeat(64)}`),
          "2026-08-13T10:55:00Z",
        );
      }
      if (revision[2] === "keyless-demo-wif-1") {
        return reply(
          revisionBody(revision[1], revision[2], "wif-1", "2026-08-13T11:38:00Z", `sha256:${"d".repeat(64)}`),
          "2026-08-13T11:41:00Z",
        );
      }
    }
    throw new Error(`unexpected URL ${url}`);
  };
}

const collectPlan = {
  version: 1,
  domain: "KEYLESS_K0_PREDISABLE_COLLECT_PLAN_V1",
  transaction_id: "predisable-collect-1",
  nonce: "predisable-public-nonce-0001",
  github: { owner, repository },
  scope,
  wif: { pool_id: "keyless-k0", provider_id: "github" },
  planned_wif_2_revision: "keyless-demo-wif-2",
  legacy_baseline: { run_id: "1401", pull_number: 6 },
  proof: { run_id: "1001" },
  cutover: { run_id: "1501", pull_number: 11 },
  approvals: {
    h1: { owner: "cherala2002", repository: "keyless-h1-probe", pull_number: 7 },
    h2: { owner, repository: "keyless-hostile", pull_number: 8 },
    h4: { owner, repository, pull_number: 9 },
    legacy: { owner, repository, pull_number: 10 },
  },
  hostile: Object.fromEntries(Object.entries(hostileFixtures).map(([id, fixture]) => [id, {
    owner: fixture.run.repository.full_name.split("/")[0],
    repository: fixture.run.repository.full_name.split("/")[1],
    run_id: String(fixture.run.id),
  }])),
  forbidden_target: forbiddenTarget,
};

const googleAuthStub = {
  getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }),
};

test("pre-disable collector emits a bundle input, archive plan, and checkpoint receipt that every verifier accepts", async () => {
  const { store, proof, receiptBytes } = await consumedProofReceipt();
  const planBytes = Buffer.from(canonicalJson(collectPlan));
  // One harness across both phases, so the two forbidden-target reads share a single timeline and
  // genuinely bracket H8. Phase one must run before any hostile probe exists.
  const fetchImpl = fetchHarness(proof);
  const forbiddenBeforeBytes = await observeK0ForbiddenBefore(planBytes, { googleAuth: googleAuthStub, fetchImpl });
  const outputs = await collectK0PreDisable(planBytes, {
    installationToken,
    googleAuth: googleAuthStub,
    challengeStore: store,
    operatorReceiptBytes: receiptBytes,
    forbiddenBeforeBytes,
    fetchImpl,
  });

  const bundleInput = JSON.parse(outputs.bundleInputBytes.toString("utf8"));
  const artifacts = new Map(bundleInput.evidence.map((envelope) => [
    envelope.id,
    Buffer.from(createEvidenceArtifact(envelope).artifact),
  ]));
  const plan = parseK0PreDisableArchivePlanBytes(outputs.archivePlanBytes);
  const semantic = await verifyK0PreDisableEvidenceSemantics(
    bundleInput.manifest,
    plan.evidence,
    async (id) => artifacts.get(id),
  );
  assert.deepEqual(semantic, { ok: true, errors: [] });
  assert.deepEqual(plan.fragment, bundleInput.manifest);

  // outputs.artifacts must be exactly what bin/k0-predisable-archive.mjs needs written to disk:
  // one entry per archive-plan evidence id, byte-identical to the independently reconstructed
  // artifact bytes above.
  assert.ok(outputs.artifacts instanceof Map);
  assert.deepEqual([...outputs.artifacts.keys()].sort(), plan.evidence.map(({ id }) => id).sort());
  for (const [id, bytes] of outputs.artifacts) {
    assert.ok(Buffer.isBuffer(bytes));
    assert.ok(bytes.equals(artifacts.get(id)), `artifact ${id} bytes do not match`);
  }

  const { archiveBytes } = await createK0PreDisableArchive(plan, artifacts);
  assert.equal(await verifyK0PreDisableArchive(archiveBytes), true);

  const receipt = parseGitHubEvidenceCheckpointReceipt(outputs.checkpointReceiptBytes);
  assert.equal(receipt.receipt.version, 1);
  assert.deepEqual(
    receipt.receipt.evidence.map(({ id }) => id),
    plan.evidence.map(({ id }) => id),
  );
  for (const record of receipt.receipt.evidence) {
    const envelope = bundleInput.evidence.find(({ id }) => id === record.id);
    assert.equal(record.kind, envelope.kind);
    assert.equal(record.locator, envelope.locator);
    assert.equal(record.recorded_at, envelope.observed_at);
    assert.equal(record.data_sha256, createHash("sha256").update(canonicalJson(envelope.data)).digest("hex"));
  }
  assert.equal(plan.fragment.wif.mode, "PREEXISTING_EXACT");
  assert.equal(plan.fragment.proof.challenge_status, "CONSUMED");
  assert.equal(plan.fragment.hostile_tests.length, 8);
  assert.equal(
    plan.evidence.some(({ id }) => id === plan.fragment.revisions.forbidden_after_source_id),
    false,
  );
});

test("phase two refuses a missing, mismatched, or noncanonical forbidden-before observation", async () => {
  const { store, proof, receiptBytes } = await consumedProofReceipt();
  const planBytes = Buffer.from(canonicalJson(collectPlan));
  const collect = (forbiddenBeforeBytes) => collectK0PreDisable(planBytes, {
    installationToken,
    googleAuth: googleAuthStub,
    challengeStore: store,
    operatorReceiptBytes: receiptBytes,
    forbiddenBeforeBytes,
    fetchImpl: fetchHarness(proof),
  });
  const valid = JSON.parse(
    (await observeK0ForbiddenBefore(planBytes, { googleAuth: googleAuthStub, fetchImpl: fetchHarness(proof) }))
      .toString("utf8"),
  );

  await assert.rejects(collect(undefined), /forbidden-before observation bytes are invalid/);
  await assert.rejects(collect(Buffer.alloc(0)), /forbidden-before observation bytes are invalid/);
  await assert.rejects(collect(Buffer.from("{")), /forbidden-before observation is not JSON/);
  for (const mutate of [
    (value) => { value.revision = "forbidden-00002"; },
    (value) => { value.release_marker = "other"; },
    (value) => { value.image_digest = `sha256:${"0".repeat(64)}`; },
    (value) => { value.service = "keyless-demo"; },
    (value) => { value.observed_at = "not-a-time"; },
    (value) => { delete value.observed_at; },
    (value) => { value.extra = 1; },
  ]) {
    const mutated = structuredClone(valid);
    mutate(mutated);
    await assert.rejects(collect(Buffer.from(canonicalJson(mutated))), /forbidden-before observation/);
  }
  // Canonical bytes only: a re-serialised-but-reordered body is refused.
  await assert.rejects(collect(Buffer.from(JSON.stringify({ observed_at: valid.observed_at, ...valid }))),
    /forbidden-before observation/);
});
