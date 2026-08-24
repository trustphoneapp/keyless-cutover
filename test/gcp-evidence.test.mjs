import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { assertCredentialFreeBytes } from "../src/credential-scan.mjs";
import { createEvidenceArtifact } from "../src/evidence-artifact.mjs";
import {
  computePreexistingWifParityHash,
  createGcpEvidenceReader,
  verifyPreexistingWifReadback,
  verifyWifReadback,
} from "../src/gcp-evidence.mjs";
import { buildWifPlan } from "../src/wif-plan.mjs";
import { validK0BundleInput, validWifAuditLog } from "./fixtures/k0-bundle.mjs";

const plan = buildWifPlan({
  project_id: "keyless-k0-demo",
  project_number: "123456789",
  pool_id: "keyless-k0",
  provider_id: "github",
  owner_id: "111",
  repository_id: "222",
  owner: "trustphoneapp",
  repository: "keyless-cutover",
  service_account: "keyless-deploy@keyless-k0-demo.iam.gserviceaccount.com",
});
const downstream = {
  version: 3,
  etag: "downstream-etag",
  bindings: [{ role: "roles/run.developer", members: [`serviceAccount:${plan.service_account}`] }],
};
const serviceAccountBefore = { version: 3, etag: "before", bindings: [] };
const serviceAccountAfter = {
  version: 3,
  etag: "after",
  bindings: [{ role: plan.impersonation_binding.role, members: [plan.impersonation_binding.member] }],
};
const provider = {
  name: plan.provider,
  state: "ACTIVE",
  oidc: { issuerUri: plan.issuer },
  attributeMapping: plan.attribute_mapping,
  attributeCondition: plan.attribute_condition,
};
const preexistingServicePolicy = {
  version: 1,
  etag: "service-etag-1",
  bindings: [{
    role: plan.impersonation_binding.role,
    members: [plan.impersonation_binding.member],
  }, {
    role: "roles/iam.serviceAccountAdmin",
    members: ["user:key-operator@example.com"],
  }],
};
const preexistingAllowedPolicy = {
  version: 1,
  etag: "allowed-etag-1",
  bindings: [{ role: "roles/run.developer", members: [`serviceAccount:${plan.service_account}`] }],
};
const preexistingForbiddenPolicy = { version: 1, etag: "forbidden-etag-1", bindings: [] };

function preexistingArguments(overrides = {}) {
  return {
    plan: { ...plan, allowed_service: "keyless-demo", forbidden_service: "keyless-forbidden" },
    serviceAccountUniqueId: "110652672782847439596",
    region: "us-central1",
    providerBefore: structuredClone(provider),
    providerAfter: structuredClone(provider),
    serviceAccountPolicyBefore: structuredClone(preexistingServicePolicy),
    serviceAccountPolicyAfter: structuredClone(preexistingServicePolicy),
    allowedPolicyBefore: structuredClone(preexistingAllowedPolicy),
    allowedPolicyAfter: structuredClone(preexistingAllowedPolicy),
    forbiddenPolicyBefore: structuredClone(preexistingForbiddenPolicy),
    forbiddenPolicyAfter: structuredClone(preexistingForbiddenPolicy),
    observedBeforeAt: "2026-08-13T11:00:00Z",
    observedAfterAt: "2026-08-13T12:00:00Z",
    ...overrides,
  };
}

function etagHash(value) {
  return createHash("sha256").update("KEYLESS_GCP_IAM_ETAG_V1\0").update(value, "utf8").digest("hex");
}
const namedRevisionName = "projects/keyless-k0-demo/locations/us-central1/services/keyless-demo/revisions/keyless-demo-wif-2";

function namedRevision(overrides = {}) {
  return {
    name: namedRevisionName,
    createTime: "2026-08-13T12:13:45.123456789Z",
    conditions: [{ type: "Ready", state: "CONDITION_SUCCEEDED" }],
    containers: [{
      image: `us-docker.pkg.dev/example/app@sha256:${"a".repeat(64)}`,
      env: [{ name: "RELEASE", value: "wif-2" }],
    }],
    ...overrides,
  };
}

function namedReader(fetchImpl) {
  return createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl,
  });
}

function namedArguments(overrides = {}) {
  return {
    projectId: "keyless-k0-demo",
    region: "us-central1",
    service: "keyless-demo",
    revision: "keyless-demo-wif-2",
    expectedReleaseMarker: "wif-2",
    ...overrides,
  };
}

const exactRevisionName = "projects/keyless-k0-demo/locations/us-central1/services/keyless-forbidden/revisions/forbidden-00001";

function exactRevision(overrides = {}) {
  return {
    name: exactRevisionName,
    createTime: "2026-08-12T10:00:00Z",
    conditions: [{ type: "Ready", state: "CONDITION_SUCCEEDED" }],
    containers: [{
      image: `us-docker.pkg.dev/example/forbidden@sha256:${"b".repeat(64)}`,
      env: [{ name: "RELEASE", value: "stable" }],
    }],
    ...overrides,
  };
}

function exactRevisionArguments(overrides = {}) {
  return {
    projectId: "keyless-k0-demo",
    region: "us-central1",
    service: "keyless-forbidden",
    revision: "forbidden-00001",
    expectedReleaseMarker: "stable",
    expectedCreateTime: "2026-08-12T10:00:00Z",
    expectedImageDigest: `sha256:${"b".repeat(64)}`,
    ...overrides,
  };
}

function exactRevisionReader(fetchImpl, counters = { auth: 0 }) {
  return createGcpEvidenceReader({
    auth: {
      getClient: async () => {
        counters.auth += 1;
        return { getRequestHeaders: async () => ({ authorization: "Bearer test" }) };
      },
    },
    fetchImpl,
  });
}

const parityPlan = {
  ...plan,
  allowed_service: "keyless-demo",
  forbidden_service: "keyless-forbidden",
};
const parityScope = {
  owner_id: "111",
  repository_id: "222",
  workflow_path: ".github/workflows/k0-deploy.yml",
  proof_workflow_path: ".github/workflows/k0-proof-v2.yml",
  legacy_workflow_path: ".github/workflows/k0-legacy.yml",
  h1_workflow_path: ".github/workflows/k0-external-hostile.yml",
  h2_workflow_path: ".github/workflows/k0-deploy.yml",
  h4_workflow_path: ".github/workflows/k0-deploy.yml",
  project_id: plan.project_id,
  project_number: plan.project_number,
  region: "us-central1",
  service_account_email: plan.service_account,
  service_account_unique_id: "110652672782847439596",
  key_id: "a".repeat(40),
  allowed_service: parityPlan.allowed_service,
  forbidden_service: parityPlan.forbidden_service,
};
const parityAccount = {
  name: `projects/${plan.project_id}/serviceAccounts/${plan.service_account}`,
  projectId: plan.project_id,
  email: plan.service_account,
  uniqueId: "110652672782847439596",
};
const parityDates = Array.from({ length: 9 }, (_, index) => `Thu, 13 Aug 2026 11:00:0${index} GMT`);

function parityHarness({ transform, onGetClient } = {}) {
  const requests = [];
  let authCalls = 0;
  const bodies = [
    provider,
    parityAccount,
    preexistingServicePolicy,
    preexistingAllowedPolicy,
    preexistingForbiddenPolicy,
    provider,
    preexistingServicePolicy,
    preexistingAllowedPolicy,
    preexistingForbiddenPolicy,
  ].map((value) => structuredClone(value));
  const reader = createGcpEvidenceReader({
    auth: {
      getClient: async () => {
        authCalls += 1;
        onGetClient?.(authCalls);
        return { getRequestHeaders: async () => ({ authorization: "Bearer test" }) };
      },
    },
    fetchImpl: async (url, options) => {
      const index = requests.length;
      requests.push({ url, options });
      const context = { index, url, options, value: bodies[index], date: parityDates[index] };
      const changed = transform?.(context);
      if (changed instanceof Response) return changed;
      const selected = changed ?? context;
      const headers = selected.date === undefined ? {} : { date: selected.date };
      return new Response(JSON.stringify(selected.value), { status: 200, headers });
    },
  });
  return { reader, requests, authCalls: () => authCalls };
}

test("GCP readback proves exact WIF trust addition and unchanged downstream IAM", () => {
  const result = verifyWifReadback({
    plan,
    serviceAccountUniqueId: "110652672782847439596",
    provider,
    serviceAccountPolicyBefore: serviceAccountBefore,
    serviceAccountPolicyAfter: serviceAccountAfter,
    allowedPolicyBefore: downstream,
    allowedPolicyAfter: structuredClone(downstream),
    forbiddenPolicyBefore: { version: 3, etag: "f1", bindings: [] },
    forbiddenPolicyAfter: { version: 3, etag: "f2", bindings: [] },
  });
  assert.deepEqual(result.provider, {
    name: plan.provider,
    config_hash: plan.provider_config_hash,
    state: "ACTIVE",
    project_id: plan.project_id,
    project_number: plan.project_number,
    service_account_email: plan.service_account,
    service_account_unique_id: "110652672782847439596",
  });
  assert.equal(result.policy.no_added_downstream_permissions, true);
  assert.match(result.policy.iam_diff_hash, /^[a-f0-9]{64}$/);
  assert.throws(() => verifyWifReadback({
    plan,
    serviceAccountUniqueId: "110652672782847439596",
    provider,
    serviceAccountPolicyBefore: serviceAccountBefore,
    serviceAccountPolicyAfter: serviceAccountAfter,
    allowedPolicyBefore: downstream,
    allowedPolicyAfter: { ...downstream, bindings: [] },
    forbiddenPolicyBefore: downstream,
    forbiddenPolicyAfter: downstream,
  }), /downstream/);
});

test("preexisting WIF readback proves exact unchanged provider and least-privilege policies", () => {
  const result = verifyPreexistingWifReadback(preexistingArguments());
  assert.equal(result.mode, "PREEXISTING_EXACT");
  assert.equal(result.provider, plan.provider);
  assert.equal(result.expected_binding_hash, plan.impersonation_binding_hash);
  assert.equal(result.no_added_downstream_permissions, true);
  assert.equal(result.no_forbidden_access, true);
  assert.equal(result.parity_hash, computePreexistingWifParityHash(result));
  assert.match(result.parity_hash, /^[a-f0-9]{64}$/);
});

test("preexisting WIF parity hashes realistic opaque etags without archiving raw bytes", () => {
  const input = preexistingArguments();
  const etags = [
    Buffer.from([7, 5, 251, 185, 140, 252, 124, 189]).toString("base64"),
    Buffer.from([8, 129, 255, 0, 173, 190, 239]).toString("base64"),
    Buffer.from([9, 224, 222, 173, 190, 239, 1]).toString("base64"),
  ];
  for (const [before, after, etag] of [
    [input.serviceAccountPolicyBefore, input.serviceAccountPolicyAfter, etags[0]],
    [input.allowedPolicyBefore, input.allowedPolicyAfter, etags[1]],
    [input.forbiddenPolicyBefore, input.forbiddenPolicyAfter, etags[2]],
  ]) before.etag = after.etag = etag;
  const result = verifyPreexistingWifReadback(input);
  assert.equal(result.service_account_etag_sha256, etagHash(etags[0]));
  assert.equal(result.allowed_etag_sha256, etagHash(etags[1]));
  assert.equal(result.forbidden_etag_sha256, etagHash(etags[2]));
  assert.equal(Object.values(result).some((value) => etags.includes(value)), false);
  const artifact = createEvidenceArtifact({
    id: "E001",
    kind: "GCP_WIF_PARITY",
    locator: "gcp:wif-parity",
    observed_at: result.observed_after_at,
    data: result,
  });
  assert.doesNotThrow(() => assertCredentialFreeBytes(Buffer.from(artifact.artifact, "utf8")));

  input.allowedPolicyAfter.etag = `${etags[1].slice(0, -1)}A`;
  assert.throws(() => verifyPreexistingWifReadback(input), /drifted/);
});

test("preexisting WIF parity rejects malformed etags and duplicate semantic grants", () => {
  for (const etag of [
    null, "", "bad\netag", "x".repeat(513),
    "\ud800high", "mid\ud800high", "high\ud800",
    "\udc00low", "mid\udc00low", "low\udc00",
  ]) {
    const input = preexistingArguments();
    input.serviceAccountPolicyBefore.etag = etag;
    input.serviceAccountPolicyAfter.etag = etag;
    assert.throws(() => verifyPreexistingWifReadback(input), /policy before is invalid/);
  }
  const duplicates = [
    (input) => {
      const human = input.serviceAccountPolicyBefore.bindings[1].members[0];
      input.serviceAccountPolicyBefore.bindings[1].members.push(human);
      input.serviceAccountPolicyAfter = structuredClone(input.serviceAccountPolicyBefore);
    },
    (input) => {
      const human = input.serviceAccountPolicyBefore.bindings[1];
      input.serviceAccountPolicyBefore.bindings.push(structuredClone(human));
      input.serviceAccountPolicyAfter = structuredClone(input.serviceAccountPolicyBefore);
    },
    (input) => {
      input.forbiddenPolicyBefore.bindings = [{
        role: "roles/run.viewer",
        members: ["user:reviewer@example.com", "user:reviewer@example.com"],
      }];
      input.forbiddenPolicyAfter = structuredClone(input.forbiddenPolicyBefore);
    },
  ];
  for (const mutate of duplicates) {
    const input = preexistingArguments();
    mutate(input);
    assert.throws(() => verifyPreexistingWifReadback(input), /duplicate IAM grants/);
  }
});

test("preexisting WIF parity preserves paired Unicode etags without replacement collisions", () => {
  const input = preexistingArguments();
  const paired = "etag-😀-𐀀";
  const replacement = "etag-�";
  const opaque = Buffer.from([7, 5, 251, 185, 140, 252, 124, 189]).toString("base64");
  for (const [before, after, etag] of [
    [input.serviceAccountPolicyBefore, input.serviceAccountPolicyAfter, paired],
    [input.allowedPolicyBefore, input.allowedPolicyAfter, replacement],
    [input.forbiddenPolicyBefore, input.forbiddenPolicyAfter, opaque],
  ]) before.etag = after.etag = etag;
  const result = verifyPreexistingWifReadback(input);
  assert.equal(result.service_account_etag_sha256, etagHash(paired));
  assert.equal(result.allowed_etag_sha256, etagHash(replacement));
  assert.equal(result.forbidden_etag_sha256, etagHash(opaque));
  assert.equal(new Set([
    result.service_account_etag_sha256,
    result.allowed_etag_sha256,
    result.forbidden_etag_sha256,
  ]).size, 3);
});

test("preexisting WIF parity treats nonduplicated split bindings as semantically equal", () => {
  const input = preexistingArguments();
  input.serviceAccountPolicyBefore.bindings[1].members.push("user:reviewer@example.com");
  input.serviceAccountPolicyAfter.bindings = [
    input.serviceAccountPolicyBefore.bindings[0],
    { role: "roles/iam.serviceAccountAdmin", members: ["user:reviewer@example.com"] },
    { role: "roles/iam.serviceAccountAdmin", members: ["user:key-operator@example.com"] },
  ];
  assert.doesNotThrow(() => verifyPreexistingWifReadback(input));
});

test("authenticated reader collects exact PREEXISTING_EXACT parity with read-only requests", async () => {
  const harness = parityHarness();
  const result = await harness.reader.readPreexistingWifParity({ plan: parityPlan, scope: parityScope });
  const accountUrl = `https://iam.googleapis.com/v1/projects/${plan.project_id}/serviceAccounts/${encodeURIComponent(plan.service_account)}`;
  const providerUrl = `https://iam.googleapis.com/v1/${plan.provider}`;
  const cloudUrl = (service) => `https://run.googleapis.com/v2/projects/${plan.project_id}/locations/us-central1/services/${service}:getIamPolicy?options.requestedPolicyVersion=3`;
  const policyBody = JSON.stringify({ options: { requestedPolicyVersion: 3 } });
  assert.deepEqual(harness.requests.map(({ url, options }) => [options.method, url, options.body]), [
    ["GET", providerUrl, undefined],
    ["GET", accountUrl, undefined],
    ["POST", `${accountUrl}:getIamPolicy`, policyBody],
    ["GET", cloudUrl(parityPlan.allowed_service), undefined],
    ["GET", cloudUrl(parityPlan.forbidden_service), undefined],
    ["GET", providerUrl, undefined],
    ["POST", `${accountUrl}:getIamPolicy`, policyBody],
    ["GET", cloudUrl(parityPlan.allowed_service), undefined],
    ["GET", cloudUrl(parityPlan.forbidden_service), undefined],
  ]);
  assert.equal(harness.authCalls(), 9);
  assert.equal(harness.requests.every(({ options }) => options.headers.get("authorization") === "Bearer test"), true);
  assert.equal(harness.requests.every(({ url, options }) => options.method === "GET"
    || (options.method === "POST" && url.endsWith(":getIamPolicy") && options.body === policyBody)), true);
  assert.equal(result.mode, "PREEXISTING_EXACT");
  assert.equal(result.region, "us-central1");
  assert.equal(result.observed_before_at, "2026-08-13T11:00:04.000Z");
  assert.equal(result.observed_after_at, "2026-08-13T11:00:08.000Z");
  assert.equal(result.service_account_unique_id, parityAccount.uniqueId);
  assert.equal(Object.values(result).some((value) => [
    preexistingServicePolicy.etag, preexistingAllowedPolicy.etag, preexistingForbiddenPolicy.etag,
  ].includes(value)), false);
});

test("authenticated parity reader accepts only the four official scoped service-account names", async () => {
  const names = [
    `projects/${plan.project_id}/serviceAccounts/${plan.service_account}`,
    `projects/${plan.project_id}/serviceAccounts/${parityScope.service_account_unique_id}`,
    `projects/-/serviceAccounts/${plan.service_account}`,
    `projects/-/serviceAccounts/${parityScope.service_account_unique_id}`,
  ];
  for (const name of names) {
    const harness = parityHarness({
      transform: ({ index, value, date }) => index === 1
        ? { value: { ...value, name }, date } : undefined,
    });
    assert.equal((await harness.reader.readPreexistingWifParity({
      plan: parityPlan, scope: parityScope,
    })).mode, "PREEXISTING_EXACT");
  }

  const attacks = [
    `projects/wrong-project/serviceAccounts/${plan.service_account}`,
    `projects/${plan.project_id}/serviceAccounts/wrong@${plan.project_id}.iam.gserviceaccount.com`,
    `projects/${plan.project_id}/serviceAccounts/999999999999999999999`,
    "malformed",
    `projects/${plan.project_id}/serviceAccounts/${encodeURIComponent(plan.service_account)}`,
    `projects/${plan.project_id}/serviceAccounts/${plan.service_account}/extra`,
    `projects/${plan.project_id}/serviceAccounts/${plan.service_account}?alt=json`,
    `projects/-/serviceAccounts/other@${plan.project_id}.iam.gserviceaccount.com`,
  ];
  for (const name of attacks) {
    const harness = parityHarness({
      transform: ({ index, value, date }) => index === 1
        ? { value: { ...value, name }, date } : undefined,
    });
    await assert.rejects(
      () => harness.reader.readPreexistingWifParity({ plan: parityPlan, scope: parityScope }),
      /service account identity/,
    );
  }
  for (const changed of [
    { projectId: "wrong-project" },
    { email: `wrong@${plan.project_id}.iam.gserviceaccount.com` },
    { uniqueId: "999999999999999999999" },
  ]) {
    const harness = parityHarness({
      transform: ({ index, value, date }) => index === 1
        ? { value: { ...value, ...changed }, date } : undefined,
    });
    await assert.rejects(
      () => harness.reader.readPreexistingWifParity({ plan: parityPlan, scope: parityScope }),
      /service account identity/,
    );
  }
});

test("preexisting WIF readback validates every documented provider field and exact snapshot parity", () => {
  const input = preexistingArguments();
  for (const current of [input.providerBefore, input.providerAfter]) {
    current.displayName = "Keyless GitHub provider";
    current.description = "Approved provider metadata";
    current.disabled = false;
    current.expireTime = "2027-08-13T11:00:00Z";
    current.oidc.allowedAudiences = [];
  }
  assert.doesNotThrow(() => verifyPreexistingWifReadback(input));

  const attacks = [
    (value) => { value.providerBefore.aws = {}; },
    (value) => { value.providerBefore.saml = {}; },
    (value) => { value.providerBefore.x509 = {}; },
    (value) => { value.providerBefore.unknown = true; },
    (value) => { value.providerBefore.oidc.unknown = true; },
    (value) => { value.providerBefore.oidc.jwksJson = "custom-key-material"; },
    (value) => { value.providerBefore.disabled = true; },
    (value) => { value.providerBefore.expireTime = "not-a-time"; },
    (value) => {
      value.providerBefore.description = "before";
      value.providerAfter.description = "after";
    },
  ];
  for (const mutate of attacks) {
    const value = preexistingArguments();
    mutate(value);
    assert.throws(() => verifyPreexistingWifReadback(value), /provider/);
  }
});

test("authenticated parity reader rejects provider, identity, and policy drift", async () => {
  const attacks = [
    ({ index, value, date }) => index === 0
      ? { value: { ...value, name: value.name.replace("/github", "/wrong") }, date } : undefined,
    ({ index, value, date }) => index === 1
      ? { value: { ...value, uniqueId: "9999999999" }, date } : undefined,
    ({ index, value, date }) => index === 3
      ? { value: { ...value, bindings: [] }, date } : undefined,
  ];
  for (const transform of attacks) {
    const { reader } = parityHarness({ transform });
    await assert.rejects(() => reader.readPreexistingWifParity({ plan: parityPlan, scope: parityScope }));
  }
  const wrongOwner = { ...parityScope, owner_id: "999" };
  const { reader } = parityHarness();
  await assert.rejects(() => reader.readPreexistingWifParity({
    plan: parityPlan, scope: wrongOwner,
  }), /output does not match/);
});

test("authenticated parity reader rejects missing, malformed, regressing, and same-second Dates", async () => {
  const attacks = [
    ({ index, value, date }) => index === 2 ? { value, date: undefined } : undefined,
    ({ index, value, date }) => index === 2 ? { value, date: "invalid" } : undefined,
    ({ index, value, date }) => index === 4
      ? { value, date: "Thu, 13 Aug 2026 10:59:59 GMT" } : undefined,
    ({ value }) => ({ value, date: parityDates[0] }),
  ];
  for (const transform of attacks) {
    const { reader } = parityHarness({ transform });
    await assert.rejects(() => reader.readPreexistingWifParity({ plan: parityPlan, scope: parityScope }), /Date|regress|boundary/);
  }
});

test("authenticated parity reader rejects HTTP, body-bound, and fatal-JSON failures", async () => {
  const date = { date: parityDates[0] };
  const responses = [
    new Response("{}", { status: 500, headers: date }),
    new Response("x".repeat(1_000_001), { status: 200, headers: date }),
    new Response(Buffer.from([0xff]), { status: 200, headers: date }),
    new Response("{", { status: 200, headers: date }),
  ];
  for (const response of responses) {
    const { reader } = parityHarness({ transform: ({ index }) => index === 0 ? response : undefined });
    await assert.rejects(() => reader.readPreexistingWifParity({ plan: parityPlan, scope: parityScope }));
  }
});

test("authenticated parity reader rejects duplicate JSON keys at every response shape", async () => {
  const rawAttacks = [
    [0, JSON.stringify(provider).replace("{", `{"name":${JSON.stringify(provider.name)},`)],
    [0, JSON.stringify(provider).replace('"oidc":{', `"oidc":{"issuerUri":${JSON.stringify(plan.issuer)},`)],
    [1, JSON.stringify(parityAccount).replace("{", `{"email":${JSON.stringify(parityAccount.email)},`)],
    [2, JSON.stringify(preexistingServicePolicy).replace("{", `{"etag":"duplicate",`)],
    [2, JSON.stringify(preexistingServicePolicy).replace("{", `{"version":3,`)],
    [2, JSON.stringify(preexistingServicePolicy).replace("{", `{"bindings":[],`)],
    [2, JSON.stringify(preexistingServicePolicy).replace('"role":', '"role":"roles/viewer","role":')],
    [2, JSON.stringify(preexistingServicePolicy).replace('"members":', '"members":[],"members":')],
    [2, JSON.stringify({
      version: 3,
      etag: "condition-etag",
      bindings: [{
        role: "roles/viewer",
        members: ["user:reviewer@example.com"],
        condition: { title: "approved", description: "", expression: "true" },
      }],
    }).replace('"condition":{', '"condition":{"title":"duplicate",')],
  ];
  for (const [target, raw] of rawAttacks) {
    const { reader } = parityHarness({
      transform: ({ index, date }) => index === target
        ? new Response(raw, { status: 200, headers: { date } }) : undefined,
    });
    await assert.rejects(
      () => reader.readPreexistingWifParity({ plan: parityPlan, scope: parityScope }),
      /duplicate JSON keys/,
    );
  }
});

test("authenticated parity reader reconstructs the complete approved plan before auth", async () => {
  const mutations = [
    (value) => { value.version = 2; },
    (value) => { value.issuer = "https://example.invalid/"; },
    (value) => { value.audience = "https://example.invalid/audience"; },
    (value) => { value.workflow_ref = value.workflow_ref.replace("main", "feature"); },
    (value) => { value.attribute_mapping["attribute.ref"] = "assertion.actor"; },
    (value) => { value.attribute_condition = value.attribute_condition.replace("refs/heads/main", "refs/heads/other"); },
    (value) => { value.provider_config_hash = "b".repeat(64); },
    (value) => { value.impersonation_binding.role = "roles/owner"; },
    (value) => { value.impersonation_binding_hash = "b".repeat(64); },
    (value) => { value.commands[0] = ["gcloud", "iam", "service-accounts", "delete", value.service_account]; },
    (value) => { value.plan_digest = "b".repeat(64); },
  ];
  for (const mutate of mutations) {
    const invalid = structuredClone(parityPlan);
    mutate(invalid);
    const harness = parityHarness();
    await assert.rejects(
      () => harness.reader.readPreexistingWifParity({ plan: invalid, scope: parityScope }),
      /approved WIF parity plan is invalid/,
    );
    assert.equal(harness.authCalls(), 0);
    assert.equal(harness.requests.length, 0);
  }
});

test("authenticated parity reader bounds streams, cancels overflow, and permits a missing length", async () => {
  const streamResponse = (chunks, headers = {}, { close = true } = {}) => {
    let cancelled = 0;
    const body = new ReadableStream({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(chunk);
        if (close) controller.close();
      },
      cancel() { cancelled += 1; },
    });
    return {
      response: new Response(body, { status: 200, headers: { date: parityDates[0], ...headers } }),
      cancelled: () => cancelled,
    };
  };

  for (const chunks of [
    [new Uint8Array(1_000_001)],
    [new Uint8Array(600_000), new Uint8Array(600_001)],
  ]) {
    const streamed = streamResponse(chunks, { "content-length": "1" }, { close: false });
    const { reader } = parityHarness({
      transform: ({ index }) => index === 0 ? streamed.response : undefined,
    });
    await assert.rejects(
      () => reader.readPreexistingWifParity({ plan: parityPlan, scope: parityScope }),
      /too large/,
    );
    assert.equal(streamed.cancelled(), 1);
  }

  const providerBytes = Buffer.from(JSON.stringify(provider));
  const streamed = streamResponse([
    providerBytes.subarray(0, 8), providerBytes.subarray(8),
  ]);
  const harness = parityHarness({
    transform: ({ index }) => index === 0 ? streamed.response : undefined,
  });
  assert.equal((await harness.reader.readPreexistingWifParity({
    plan: parityPlan, scope: parityScope,
  })).mode, "PREEXISTING_EXACT");

  const noBody = new Response(null, { status: 200, headers: { date: parityDates[0] } });
  const missing = parityHarness({ transform: ({ index }) => index === 0 ? noBody : undefined });
  await assert.rejects(
    () => missing.reader.readPreexistingWifParity({ plan: parityPlan, scope: parityScope }),
    /failed/,
  );
});

test("authenticated parity reader snapshots transport time before streaming awaits", async () => {
  let response;
  const body = new ReadableStream({
    pull(controller) {
      response.headers.set("date", "Thu, 13 Aug 2026 10:00:00 GMT");
      controller.enqueue(Buffer.from(JSON.stringify(preexistingForbiddenPolicy)));
      controller.close();
    },
  }, { highWaterMark: 0 });
  response = new Response(body, { status: 200, headers: { date: parityDates[4] } });
  const harness = parityHarness({
    transform: ({ index }) => index === 4 ? response : undefined,
  });
  const result = await harness.reader.readPreexistingWifParity({ plan: parityPlan, scope: parityScope });
  assert.equal(result.observed_before_at, "2026-08-13T11:00:04.000Z");
});

test("authenticated parity reader snapshots the approved plan before awaiting", async () => {
  const mutable = structuredClone(parityPlan);
  const mutableScope = structuredClone(parityScope);
  const harness = parityHarness({
    onGetClient(call) {
      if (call !== 1) return;
      mutable.project_id = "wrong-project";
      mutable.allowed_service = "wrong-service";
      mutable.impersonation_binding.member = "wrong";
      mutableScope.region = "us-east1";
      mutableScope.service_account_unique_id = "9999999999";
    },
  });
  const result = await harness.reader.readPreexistingWifParity({ plan: mutable, scope: mutableScope });
  assert.equal(result.project_id, parityPlan.project_id);
  assert.equal(result.allowed_service, parityPlan.allowed_service);
  assert.equal(result.expected_binding_hash, parityPlan.impersonation_binding_hash);
  assert.equal(harness.requests.every(({ url }) => !url.includes("wrong")), true);
});

test("authenticated parity reader rejects accessor, Proxy, and non-JSON plans before auth", async () => {
  let getterCalls = 0;
  const accessor = structuredClone(parityPlan);
  Object.defineProperty(accessor, "project_id", {
    enumerable: true,
    get() { getterCalls += 1; return parityPlan.project_id; },
  });
  const nestedProxy = structuredClone(parityPlan);
  nestedProxy.impersonation_binding = new Proxy(nestedProxy.impersonation_binding, {});
  for (const invalid of [accessor, new Proxy(structuredClone(parityPlan), {}), nestedProxy, {
    ...structuredClone(parityPlan), invalid: undefined,
  }, { ...structuredClone(parityPlan), unknown: "value" }]) {
    const harness = parityHarness();
    await assert.rejects(() => harness.reader.readPreexistingWifParity({ plan: invalid, scope: parityScope }), /plan.*is invalid/);
    assert.equal(harness.authCalls(), 0);
    assert.equal(harness.requests.length, 0);
  }
  assert.equal(getterCalls, 0);

  const scopeAccessor = structuredClone(parityScope);
  Object.defineProperty(scopeAccessor, "region", {
    enumerable: true,
    get() { return parityScope.region; },
  });
  for (const invalidScope of [scopeAccessor, new Proxy(structuredClone(parityScope), {})]) {
    const harness = parityHarness();
    await assert.rejects(() => harness.reader.readPreexistingWifParity({
      plan: parityPlan, scope: invalidScope,
    }), /scope.*is invalid/);
    assert.equal(harness.authCalls(), 0);
    assert.equal(harness.requests.length, 0);
  }
  const mismatchedScope = { ...parityScope, project_id: "wrong-project" };
  const harness = parityHarness();
  await assert.rejects(() => harness.reader.readPreexistingWifParity({
    plan: parityPlan, scope: mismatchedScope,
  }), /plan scope is invalid/);
  assert.equal(harness.authCalls(), 0);
  assert.equal(harness.requests.length, 0);
});

test("preexisting WIF readback rejects alternate principals, roles, duplicates, and conditions", () => {
  const attacks = [
    (input) => {
      const extra = `principalSet://iam.googleapis.com/projects/${plan.project_number}/locations/global/workloadIdentityPools/keyless/attribute.repo_id/999`;
      input.serviceAccountPolicyBefore.bindings.push({ role: plan.impersonation_binding.role, members: [extra] });
      input.serviceAccountPolicyAfter = structuredClone(input.serviceAccountPolicyBefore);
    },
    (input) => {
      input.serviceAccountPolicyBefore.bindings[0].members.push(plan.impersonation_binding.member);
      input.serviceAccountPolicyAfter = structuredClone(input.serviceAccountPolicyBefore);
    },
    (input) => {
      input.serviceAccountPolicyBefore.bindings[0].role = "roles/owner";
      input.serviceAccountPolicyAfter = structuredClone(input.serviceAccountPolicyBefore);
    },
    (input) => {
      input.serviceAccountPolicyBefore.bindings[0].condition = {
        title: "alternate", description: "", expression: "true",
      };
      input.serviceAccountPolicyAfter = structuredClone(input.serviceAccountPolicyBefore);
    },
  ];
  for (const mutate of attacks) {
    const input = preexistingArguments();
    mutate(input);
    assert.throws(() => verifyPreexistingWifReadback(input), /WIF policy|duplicate IAM grants/);
  }
});

test("preexisting WIF readback rejects provider, policy, etag, forbidden-access, and time drift", () => {
  const attacks = [
    (input) => { input.providerAfter.attributeCondition = "false"; },
    (input) => {
      input.providerBefore.attributeCondition = "false";
      input.providerAfter.attributeCondition = "false";
    },
    (input) => { input.serviceAccountPolicyAfter.bindings[1].members = ["user:other@example.com"]; },
    (input) => { input.serviceAccountPolicyAfter.etag = "different"; },
    (input) => { input.allowedPolicyAfter.bindings = []; },
    (input) => { input.allowedPolicyAfter.etag = "different"; },
    (input) => {
      input.allowedPolicyBefore.bindings.push({
        role: "roles/run.admin", members: [`serviceAccount:${plan.service_account}`],
      });
      input.allowedPolicyAfter = structuredClone(input.allowedPolicyBefore);
    },
    (input) => {
      input.forbiddenPolicyBefore.bindings = [{
        role: "roles/run.developer", members: [`serviceAccount:${plan.service_account}`],
      }];
      input.forbiddenPolicyAfter = structuredClone(input.forbiddenPolicyBefore);
    },
    (input) => {
      input.forbiddenPolicyBefore.bindings = [{
        role: "roles/run.viewer", members: [plan.impersonation_binding.member],
      }];
      input.forbiddenPolicyAfter = structuredClone(input.forbiddenPolicyBefore);
    },
    (input) => { input.observedAfterAt = input.observedBeforeAt; },
  ];
  for (const mutate of attacks) {
    const input = preexistingArguments();
    mutate(input);
    assert.throws(() => verifyPreexistingWifReadback(input));
  }
});

test("GCP evidence reader uses ADC and normalizes the latest ready revision", async () => {
  const requests = [];
  const reader = createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => new Headers({ authorization: "Bearer test" }) }) },
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify(url.includes("/revisions/") ? {
          name: "projects/keyless-k0-demo/locations/us-central1/services/keyless-demo/revisions/keyless-demo-wif-2",
          createTime: "2026-08-13T12:13:45.123456789Z",
          containers: [{
            image: `us-docker.pkg.dev/example/app@sha256:${"a".repeat(64)}`,
            env: [{ name: "RELEASE", value: "wif-2" }],
          }],
        } : {
          latestReadyRevision: "projects/keyless-k0-demo/locations/us-central1/services/keyless-demo/revisions/keyless-demo-wif-2",
        }),
      };
    },
  });
  assert.deepEqual(await reader.readCloudRunRevision({
    projectId: "keyless-k0-demo", region: "us-central1", service: "keyless-demo",
  }), {
    project_id: "keyless-k0-demo",
    region: "us-central1",
    service: "keyless-demo",
    revision: "keyless-demo-wif-2",
    create_time: "2026-08-13T12:13:45.123456789Z",
    release_marker: "wif-2",
    image_digest: `sha256:${"a".repeat(64)}`,
  });
  assert.equal(requests.length, 2);
  assert.equal(requests[0].options.headers.get("authorization"), "Bearer test");
  assert.equal(requests[0].options.headers.get("content-type"), "application/json");
});

test("GCP evidence reader reads one exact named ready revision with transport observation time", async () => {
  const requests = [];
  const reader = namedReader(async (url, options) => {
    requests.push({ url, options });
    return new Response(JSON.stringify(namedRevision()), {
      status: 200,
      headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" },
    });
  });
  assert.deepEqual(await reader.readNamedCloudRunRevision(namedArguments()), {
    project_id: "keyless-k0-demo",
    region: "us-central1",
    service: "keyless-demo",
    revision: "keyless-demo-wif-2",
    create_time: "2026-08-13T12:13:45.123456789Z",
    release_marker: "wif-2",
    image_digest: `sha256:${"a".repeat(64)}`,
    observed_at: "2026-08-13T12:14:00.000Z",
  });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, `https://run.googleapis.com/v2/${namedRevisionName}`);
  assert.equal(requests[0].options.method, "GET");
  assert.equal(requests[0].options.headers.get("authorization"), "Bearer test");
});

test("exact Cloud Run observation reads an arbitrary pinned forbidden revision once", async () => {
  const requests = [];
  const reader = exactRevisionReader(async (url, options) => {
    requests.push({ url, options });
    return new Response(JSON.stringify(exactRevision()), {
      status: 200,
      headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" },
    });
  });
  assert.deepEqual(await reader.readExactCloudRunRevisionObservation(exactRevisionArguments()), {
    project_id: "keyless-k0-demo",
    region: "us-central1",
    service: "keyless-forbidden",
    revision: "forbidden-00001",
    create_time: "2026-08-12T10:00:00Z",
    release_marker: "stable",
    image_digest: `sha256:${"b".repeat(64)}`,
    observed_at: "2026-08-13T12:14:00.000Z",
  });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, `https://run.googleapis.com/v2/${exactRevisionName}`);
  assert.equal(requests[0].options.method, "GET");
  assert.equal(requests[0].options.body, undefined);
  assert.equal(requests[0].options.headers.get("authorization"), "Bearer test");
});

test("exact Cloud Run observation rejects aliases and malformed expectations before authentication", async () => {
  const counters = { auth: 0, fetch: 0 };
  const reader = exactRevisionReader(async () => {
    counters.fetch += 1;
    throw new Error("fetch must not run");
  }, counters);
  const invalid = [
    exactRevisionArguments({ projectId: "wrong" }),
    exactRevisionArguments({ region: "us/central1" }),
    exactRevisionArguments({ service: "keyless-forbidden-" }),
    exactRevisionArguments({ service: "keyless%2dforbidden" }),
    exactRevisionArguments({ revision: "latest" }),
    exactRevisionArguments({ revision: "forbidden/00001" }),
    exactRevisionArguments({ revision: "forbidden-00001?view=full" }),
    exactRevisionArguments({ revision: "forbidden%2d00001" }),
    exactRevisionArguments({ revision: "forbidden-00001\n" }),
    exactRevisionArguments({ expectedReleaseMarker: "Stable" }),
    exactRevisionArguments({ expectedCreateTime: "2026-02-29T10:00:00Z" }),
    exactRevisionArguments({ expectedImageDigest: `sha256:${"B".repeat(64)}` }),
    { ...exactRevisionArguments(), unknown: true },
  ];
  for (const input of invalid) {
    await assert.rejects(() => reader.readExactCloudRunRevisionObservation(input));
  }
  let getterCalls = 0;
  const accessor = Object.defineProperty(exactRevisionArguments(), "revision", {
    enumerable: true,
    get() { getterCalls += 1; return "forbidden-00001"; },
  });
  await assert.rejects(() => reader.readExactCloudRunRevisionObservation(accessor));
  await assert.rejects(() => reader.readExactCloudRunRevisionObservation(new Proxy(exactRevisionArguments(), {})));
  assert.equal(getterCalls, 0);
  assert.equal(counters.auth, 0);
  assert.equal(counters.fetch, 0);
});

test("exact Cloud Run observation rejects every resource and expected-value drift", async () => {
  const bodies = [
    exactRevision({ name: exactRevisionName.replace("keyless-k0-demo", "wrong-project") }),
    exactRevision({ name: exactRevisionName.replace("us-central1", "us-east1") }),
    exactRevision({ name: exactRevisionName.replace("keyless-forbidden", "other-service") }),
    exactRevision({ name: exactRevisionName.replace("forbidden-00001", "forbidden-00002") }),
    exactRevision({ name: exactRevisionName.replace("forbidden-00001", "latest") }),
    exactRevision({ createTime: "2026-08-12T10:00:01Z" }),
    exactRevision({ conditions: [] }),
    exactRevision({ conditions: [{ type: "Ready", state: "CONDITION_FAILED" }] }),
    exactRevision({ conditions: [{ type: "Ready", state: "CONDITION_SUCCEEDED" }, { type: "Ready", state: "CONDITION_SUCCEEDED" }] }),
    exactRevision({ containers: [] }),
    exactRevision({ containers: [exactRevision().containers[0], exactRevision().containers[0]] }),
    exactRevision({ containers: [{
      ...exactRevision().containers[0], env: [{ name: "RELEASE", value: "changed" }],
    }] }),
    exactRevision({ containers: [{
      ...exactRevision().containers[0], image: `us-docker.pkg.dev/example/forbidden@sha256:${"c".repeat(64)}`,
    }] }),
    { ...exactRevision(), nextPageToken: "unexpected" },
  ];
  for (const body of bodies) {
    const reader = exactRevisionReader(async () => new Response(JSON.stringify(body), {
      status: 200,
      headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" },
    }));
    await assert.rejects(() => reader.readExactCloudRunRevisionObservation(exactRevisionArguments()));
  }
  for (const argumentsValue of [
    exactRevisionArguments({ expectedReleaseMarker: "stable-2" }),
    exactRevisionArguments({ expectedCreateTime: "2026-08-12T10:00:01Z" }),
    exactRevisionArguments({ expectedImageDigest: `sha256:${"c".repeat(64)}` }),
  ]) {
    const reader = exactRevisionReader(async () => new Response(JSON.stringify(exactRevision()), {
      status: 200,
      headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" },
    }));
    await assert.rejects(() => reader.readExactCloudRunRevisionObservation(argumentsValue));
  }
  const future = exactRevisionReader(async () => new Response(JSON.stringify(exactRevision()), {
    status: 200,
    headers: { date: "Wed, 12 Aug 2026 09:59:59 GMT" },
  }));
  await assert.rejects(() => future.readExactCloudRunRevisionObservation(exactRevisionArguments()), /after observation/);
});

test("exact Cloud Run observation snapshots input and authenticated response primitives", async () => {
  const input = exactRevisionArguments();
  const body = exactRevision();
  const bytes = Buffer.from(JSON.stringify(body));
  let releaseBody;
  let notifyRead;
  const bodyGate = new Promise((resolve) => { releaseBody = resolve; });
  const readStarted = new Promise((resolve) => { notifyRead = resolve; });
  const headers = new Headers({ date: "Thu, 13 Aug 2026 12:14:00 GMT" });
  let read = false;
  const response = {
    status: 200,
    ok: true,
    headers,
    body: { getReader: () => ({
      async read() {
        if (read) return { done: true, value: undefined };
        read = true;
        notifyRead();
        await bodyGate;
        return { done: false, value: bytes };
      },
      async cancel() {},
    }) },
  };
  const reader = exactRevisionReader(async () => response);
  const pending = reader.readExactCloudRunRevisionObservation(input);
  input.projectId = "mutated-project";
  input.revision = "mutated-revision";
  body.name = "mutated-response-object";
  await readStarted;
  headers.set("date", "invalid-after-capture");
  releaseBody();
  const result = await pending;
  assert.equal(result.project_id, "keyless-k0-demo");
  assert.equal(result.revision, "forbidden-00001");
  assert.equal(result.observed_at, "2026-08-13T12:14:00.000Z");
});

test("exact Cloud Run observation fails statically on transport and bounded-body attacks", async () => {
  const marker = `ya${"29"}.${"z".repeat(24)}`;
  const multipleDates = new Headers();
  multipleDates.append("date", "Thu, 13 Aug 2026 12:14:00 GMT");
  multipleDates.append("date", "Thu, 13 Aug 2026 12:14:01 GMT");
  const responses = [
    () => new Response(JSON.stringify(exactRevision()), { status: 200 }),
    () => new Response(JSON.stringify(exactRevision()), {
      status: 200, headers: { date: "invalid" },
    }),
    () => new Response(JSON.stringify(exactRevision()), {
      status: 200, headers: multipleDates,
    }),
    () => new Response(JSON.stringify(exactRevision()), {
      status: 201, headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" },
    }),
    () => new Response(Buffer.from([0xff]), {
      status: 200, headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" },
    }),
    () => new Response(`{"name":"duplicate","name":${JSON.stringify(exactRevisionName)}}`, {
      status: 200, headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" },
    }),
    () => new Response(Buffer.alloc(1_000_001, 0x61), {
      status: 200, headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" },
    }),
  ];
  for (const createResponse of responses) {
    const reader = exactRevisionReader(async () => createResponse());
    await assert.rejects(() => reader.readExactCloudRunRevisionObservation(exactRevisionArguments()));
  }

  for (const reader of [
    exactRevisionReader(async () => { throw new Error(marker); }),
    createGcpEvidenceReader({ auth: { getClient: async () => { throw new Error(marker); } } }),
    exactRevisionReader(async () => ({
      status: 200,
      ok: true,
      headers: new Headers({ date: "Thu, 13 Aug 2026 12:14:00 GMT" }),
      body: { getReader: () => ({
        read: async () => { throw new Error(marker); },
        cancel: async () => {},
      }) },
    })),
  ]) {
    await assert.rejects(
      () => reader.readExactCloudRunRevisionObservation(exactRevisionArguments()),
      (error) => !error.message.includes(marker),
    );
  }

  let cancelled = 0;
  let sent = false;
  const overflow = exactRevisionReader(async () => ({
    status: 200,
    ok: true,
    headers: new Headers({ date: "Thu, 13 Aug 2026 12:14:00 GMT" }),
    body: { getReader: () => ({
      async read() {
        if (sent) return { done: true, value: undefined };
        sent = true;
        return { done: false, value: new Uint8Array(1_000_001) };
      },
      async cancel() { cancelled += 1; },
    }) },
  }));
  await assert.rejects(() => overflow.readExactCloudRunRevisionObservation(exactRevisionArguments()), /too large/);
  assert.equal(cancelled, 1);
});

test("named Cloud Run revision rejects resource and latest-revision substitution", async () => {
  const names = [
    namedRevisionName.replace("keyless-k0-demo", "wrong-project"),
    namedRevisionName.replace("us-central1", "us-east1"),
    namedRevisionName.replace("/keyless-demo/", "/wrong-service/"),
    namedRevisionName.replace("keyless-demo-wif-2", "keyless-demo-wif-3"),
    "projects/keyless-k0-demo/locations/us-central1/services/keyless-demo/revisions/latest",
  ];
  for (const name of names) {
    const reader = namedReader(async () => new Response(JSON.stringify(namedRevision({ name })), {
      status: 200,
      headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" },
    }));
    await assert.rejects(() => reader.readNamedCloudRunRevision(namedArguments()), /identity/);
  }
});

test("named Cloud Run revision rejects caller aliases and wrong release identity before fetch", async () => {
  let fetches = 0;
  const reader = namedReader(async () => {
    fetches += 1;
    throw new Error("fetch must not run");
  });
  for (const argumentsValue of [
    namedArguments({ revision: "latest" }),
    namedArguments({ revision: "keyless-demo-wif-3" }),
    namedArguments({ revision: "keyless-demo-wif-2-extra" }),
    namedArguments({
      service: "a".repeat(60),
      revision: `${"a".repeat(60)}-wif-2`,
    }),
  ]) {
    await assert.rejects(() => reader.readNamedCloudRunRevision(argumentsValue), /revision/);
  }
  assert.equal(fetches, 0);
});

test("named Cloud Run revision rejects marker, image, container, readiness, and occurrence drift", async () => {
  const digest = `sha256:${"a".repeat(64)}`;
  const bodies = [
    namedRevision({ containers: [{
      image: `example/app@sha256:${"a".repeat(64)}`,
      env: [{ name: "RELEASE", value: "wrong" }],
    }] }),
    namedRevision({ containers: [{ image: "example/app:latest", env: [{ name: "RELEASE", value: "wif-2" }] }] }),
    namedRevision({ containers: [{ image: `@${digest}`, env: [{ name: "RELEASE", value: "wif-2" }] }] }),
    namedRevision({ containers: [{ image: `example/app:tag@${digest}`, env: [{ name: "RELEASE", value: "wif-2" }] }] }),
    namedRevision({ containers: [{ image: `example /app@${digest}`, env: [{ name: "RELEASE", value: "wif-2" }] }] }),
    namedRevision({ containers: [{ image: `EXAMPLE/app@${digest}`, env: [{ name: "RELEASE", value: "wif-2" }] }] }),
    namedRevision({ containers: [namedRevision().containers[0], namedRevision().containers[0]] }),
    namedRevision({ conditions: [] }),
    namedRevision({ conditions: [{ type: "Ready", state: "CONDITION_FAILED" }] }),
    namedRevision({ createTime: "2026-02-29T12:13:45Z" }),
  ];
  for (const body of bodies) {
    const reader = namedReader(async () => new Response(JSON.stringify(body), {
      status: 200,
      headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" },
    }));
    await assert.rejects(() => reader.readNamedCloudRunRevision(namedArguments()));
  }
  const regressing = namedReader(async () => new Response(JSON.stringify(namedRevision()), {
    status: 200,
    headers: { date: "Thu, 13 Aug 2026 12:13:45 GMT" },
  }));
  await assert.rejects(() => regressing.readNamedCloudRunRevision(namedArguments()), /regresses/);
});

test("named Cloud Run revision accepts exact Artifact Registry and canonical OCI image names", async () => {
  const digest = `sha256:${"a".repeat(64)}`;
  const maxRegistry = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(61)}`;
  for (const image of [
    `us-docker.pkg.dev/example/app@${digest}`,
    `europe-west1-docker.pkg.dev/example-project/repository/image@${digest}`,
    `gcr.io/keyless-k0-demo/repo.name/image-name_2@${digest}`,
    `gcr.io/keyless-k0-demo/image--name/image__name@${digest}`,
    `a/${"b".repeat(253)}@${digest}`,
    `example.com/${"a".repeat(200)}@${digest}`,
    `${maxRegistry}/x@${digest}`,
  ]) {
    const reader = namedReader(async () => new Response(JSON.stringify(namedRevision({
      containers: [{ image, env: [{ name: "RELEASE", value: "wif-2" }] }],
    })), {
      status: 200,
      headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" },
    }));
    assert.equal((await reader.readNamedCloudRunRevision(namedArguments())).image_digest, digest);
  }
});

test("named Cloud Run revision rejects malformed registries and ambiguous OCI paths", async () => {
  const digest = `sha256:${"a".repeat(64)}`;
  const invalidImages = [
    `.example.com/repo/image@${digest}`,
    `example..com/repo/image@${digest}`,
    `-example.com/repo/image@${digest}`,
    `example-.com/repo/image@${digest}`,
    `${"a".repeat(64)}.example/repo/image@${digest}`,
    `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(62)}/x@${digest}`,
    `registry_example.com/repo/image@${digest}`,
    `example.com:443/repo/image@${digest}`,
    `user@example.com/repo/image@${digest}`,
    `example.com@${digest}`,
    `example.com//image@${digest}`,
    `example.com/-repo/image@${digest}`,
    `example.com/repo-/image@${digest}`,
    `example.com/repo..name/image@${digest}`,
    `example.com/repo___name/image@${digest}`,
    `example.com/repo._name/image@${digest}`,
    `example.com/repo_.name/image@${digest}`,
    `a/${"b".repeat(254)}@${digest}`,
    `example.com/repo/Image@${digest}`,
    `example.com/repo/image:tag@${digest}`,
    `example.com/repo/image?query@${digest}`,
    `example.com/repo/image#fragment@${digest}`,
    `example.com/repo/%69mage@${digest}`,
  ];
  for (const image of invalidImages) {
    const reader = namedReader(async () => new Response(JSON.stringify(namedRevision({
      containers: [{ image, env: [{ name: "RELEASE", value: "wif-2" }] }],
    })), {
      status: 200,
      headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" },
    }));
    await assert.rejects(
      () => reader.readNamedCloudRunRevision(namedArguments()), /image digest/,
    );
  }
});

test("named Cloud Run revision rejects invalid transport and bounded response bodies", async () => {
  const multiple = new Headers();
  multiple.append("date", "Thu, 13 Aug 2026 12:14:00 GMT");
  multiple.append("date", "Thu, 13 Aug 2026 12:14:01 GMT");
  const responses = [
    () => new Response(JSON.stringify(namedRevision()), { status: 200 }),
    () => new Response(JSON.stringify(namedRevision()), { status: 200, headers: multiple }),
    () => new Response(JSON.stringify(namedRevision()), { status: 200, headers: { date: "invalid" } }),
    () => new Response("{", { status: 200, headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" } }),
    () => new Response(JSON.stringify({ ...namedRevision(), nextPageToken: "unexpected" }), {
      status: 200, headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" },
    }),
    () => new Response(JSON.stringify(namedRevision()), {
      status: 201, headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" },
    }),
    () => new Response(JSON.stringify({ padding: "x".repeat(1_000_000) }), {
      status: 200, headers: { date: "Thu, 13 Aug 2026 12:14:00 GMT" },
    }),
  ];
  for (const createResponse of responses) {
    const reader = namedReader(async () => createResponse());
    await assert.rejects(() => reader.readNamedCloudRunRevision(namedArguments()));
  }
});

test("GCP evidence reader collects one exact canonical WIF audit projection", async () => {
  const input = validK0BundleInput();
  const audit = JSON.parse(validWifAuditLog(input.manifest));
  let requestBody;
  const reader = createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async (_url, options) => {
      requestBody = JSON.parse(options.body);
      return { ok: true, status: 200, text: async () => JSON.stringify(audit) };
    },
  });
  const projection = await reader.readWifAuditEvidence({
    projectId: input.manifest.scope.project_id,
    provider: input.manifest.wif.provider,
    serviceAccountEmail: input.manifest.scope.service_account_email,
    serviceAccountUniqueId: input.manifest.scope.service_account_unique_id,
    startTime: "2026-08-13T12:13:00Z",
    endTime: "2026-08-13T12:14:00Z",
  });
  assert.deepEqual(JSON.parse(projection), audit);
  assert.deepEqual(JSON.parse(projection).entries[0].protoPayload.request, {
    "@type": "type.googleapis.com/google.identity.sts.v1.ExchangeTokenRequest",
    grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
  });
  assert.equal(requestBody.pageSize, 2);
  assert.match(requestBody.filter, /ExchangeToken/);
  assert.match(requestBody.filter, /GenerateAccessToken/);
});

test("GCP WIF audit reader accepts the live audit shape and strips its issued token", async () => {
  const input = validK0BundleInput();
  // Live 2026-08 Cloud Audit Logs shape: extra principal and request fields, plus the issued token prefix.
  const audit = JSON.parse(validWifAuditLog(input.manifest));
  const token = `ya29.${"c".repeat(40)}`;
  for (const entry of audit.entries) {
    entry.protoPayload.authenticationInfo.loggableShortLivedCredential = token;
    entry.protoPayload.authenticationInfo.principalEmail = input.manifest.scope.service_account_email;
  }
  audit.entries[1].protoPayload.request.lifetime = "3600s";
  audit.entries[1].protoPayload.request.scope = ["https://www.googleapis.com/auth/cloud-platform"];
  const reader = createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async () => ({ ok: true, status: 200, text: async () => JSON.stringify(audit) }),
  });
  const projection = await reader.readWifAuditEvidence({
    projectId: input.manifest.scope.project_id,
    provider: input.manifest.wif.provider,
    serviceAccountEmail: input.manifest.scope.service_account_email,
    serviceAccountUniqueId: input.manifest.scope.service_account_unique_id,
    startTime: "2026-08-13T12:13:00Z",
    endTime: "2026-08-13T12:14:00Z",
  });
  assert.equal(projection.includes(token), false);
  assert.doesNotThrow(() => assertCredentialFreeBytes(projection));
  const projected = JSON.parse(projection);
  assert.equal(projected.entries.some(({ protoPayload }) =>
    "loggableShortLivedCredential" in protoPayload.authenticationInfo), false);
  assert.equal(projected.entries[1].protoPayload.authenticationInfo.principalEmail,
    input.manifest.scope.service_account_email);
  assert.deepEqual(projected.entries[1].protoPayload.request, {
    "@type": "type.googleapis.com/google.iam.credentials.v1.GenerateAccessTokenRequest",
    lifetime: "3600s",
    name: `projects/-/serviceAccounts/${input.manifest.scope.service_account_email}`,
    scope: ["https://www.googleapis.com/auth/cloud-platform"],
  });
});

test("GCP WIF audit reader rejects wrong documented STS request values", async () => {
  const input = validK0BundleInput();
  for (const [field, value] of [
    ["@type", "wrong"],
    ["grantType", "wrong"],
  ]) {
    const audit = JSON.parse(validWifAuditLog(input.manifest));
    audit.entries[0].protoPayload.request[field] = value;
    const reader = createGcpEvidenceReader({
      auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
      fetchImpl: async () => ({ ok: true, status: 200, text: async () => JSON.stringify(audit) }),
    });
    await assert.rejects(reader.readWifAuditEvidence({
      projectId: input.manifest.scope.project_id,
      provider: input.manifest.wif.provider,
      serviceAccountEmail: input.manifest.scope.service_account_email,
      serviceAccountUniqueId: input.manifest.scope.service_account_unique_id,
      startTime: "2026-08-13T12:13:00Z",
      endTime: "2026-08-13T12:14:00Z",
    }), /STS audit request/);
  }
});

test("GCP WIF audit reader rejects raw STS token fields and arbitrary extras", async () => {
  const input = validK0BundleInput();
  for (const field of ["subject_token", "actor_token", "extra"]) {
    const audit = JSON.parse(validWifAuditLog(input.manifest));
    audit.entries[0].protoPayload.request[field] = "forbidden";
    const reader = createGcpEvidenceReader({
      auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
      fetchImpl: async () => ({ ok: true, status: 200, text: async () => JSON.stringify(audit) }),
    });
    await assert.rejects(reader.readWifAuditEvidence({
      projectId: input.manifest.scope.project_id,
      provider: input.manifest.wif.provider,
      serviceAccountEmail: input.manifest.scope.service_account_email,
      serviceAccountUniqueId: input.manifest.scope.service_account_unique_id,
      startTime: "2026-08-13T12:13:00Z",
      endTime: "2026-08-13T12:14:00Z",
    }), /STS audit request/);
  }
});

test("GCP WIF audit reader rejects pagination", async () => {
  const input = validK0BundleInput();
  const audit = JSON.parse(validWifAuditLog(input.manifest));
  const reader = createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ...audit, nextPageToken: "more" }),
    }),
  });
  await assert.rejects(reader.readWifAuditEvidence({
    projectId: input.manifest.scope.project_id,
    provider: input.manifest.wif.provider,
    serviceAccountEmail: input.manifest.scope.service_account_email,
    serviceAccountUniqueId: input.manifest.scope.service_account_unique_id,
    startTime: "2026-08-13T12:13:00Z",
    endTime: "2026-08-13T12:14:00Z",
  }), /paginated/);
});

function observedJsonResponse(value, {
  date = "Thu, 13 Aug 2026 12:13:31 GMT",
  status = 200,
  raw,
  headers = {},
} = {}) {
  return new Response(raw ?? JSON.stringify(value), {
    status,
    headers: { ...(date === undefined ? {} : { date }), ...headers },
  });
}

function wifObservedArguments(input = validK0BundleInput()) {
  return {
    projectId: input.manifest.scope.project_id,
    provider: input.manifest.wif.provider,
    serviceAccountEmail: input.manifest.scope.service_account_email,
    serviceAccountUniqueId: input.manifest.scope.service_account_unique_id,
    startTime: "2026-08-13T12:13:00Z",
    endTime: "2026-08-13T12:14:00Z",
  };
}

test("observed WIF audit reader returns the exact projection and authenticated transport time", async () => {
  const input = validK0BundleInput();
  const audit = JSON.parse(validWifAuditLog(input.manifest));
  let requestBody;
  const reader = createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async (_url, options) => {
      requestBody = JSON.parse(options.body);
      return observedJsonResponse(audit);
    },
  });
  const result = await reader.readWifAuditEvidenceObserved(wifObservedArguments(input));
  assert.equal(result.observedAt, "2026-08-13T12:13:31.000Z");
  assert.deepEqual(JSON.parse(result.projection), audit);
  assert.equal(Buffer.isBuffer(result.projection), true);
  assert.equal(result.projection.equals(Buffer.from(validWifAuditLog(input.manifest))), true);
  assert.equal(requestBody.pageSize, 2);
});

test("observed WIF audit reader rejects transport, parsing, identity, timeline, and pagination failures", async () => {
  const input = validK0BundleInput();
  const valid = JSON.parse(validWifAuditLog(input.manifest));
  const cases = [
    { response: () => observedJsonResponse(valid, { date: null }), pattern: /Date/ },
    { response: () => observedJsonResponse(valid, { date: "invalid" }), pattern: /Date/ },
    { response: () => observedJsonResponse(valid, { status: 201 }), pattern: /response/ },
    { response: () => observedJsonResponse(valid, { raw: Buffer.from([0xff]) }), pattern: /valid JSON/ },
    {
      response: () => observedJsonResponse(valid, {
        raw: `{"entries":[],"entries":${JSON.stringify(valid.entries)}}`,
      }),
      pattern: /duplicate/,
    },
    { response: () => observedJsonResponse({ ...valid, nextPageToken: "more" }), pattern: /paginated/ },
    { response: () => observedJsonResponse({ entries: [valid.entries[0]] }), pattern: /ambiguous/ },
    {
      response: () => {
        const changed = structuredClone(valid);
        changed.entries[1].protoPayload.request.name = "projects/-/serviceAccounts/other@example.iam.gserviceaccount.com";
        return observedJsonResponse(changed);
      },
      pattern: /scope|identity|service account/,
    },
    {
      response: () => observedJsonResponse(valid, { date: "Thu, 13 Aug 2026 12:13:29 GMT" }),
      pattern: /observation/,
    },
    {
      response: () => observedJsonResponse(valid, {
        raw: JSON.stringify({ padding: "x".repeat(1_000_001) }),
      }),
      pattern: /too large/,
    },
  ];
  for (const { response, pattern } of cases) {
    const reader = createGcpEvidenceReader({
      auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
      fetchImpl: async () => response(),
    });
    await assert.rejects(reader.readWifAuditEvidenceObserved(wifObservedArguments(input)), pattern);
  }
});

test("observed WIF transport snapshots response primitives and sanitizes hostile failures", async () => {
  const input = validK0BundleInput();
  const bytes = Buffer.from(validWifAuditLog(input.manifest));
  let read = false;
  let date = "Thu, 13 Aug 2026 12:13:31 GMT";
  const response = {
    ok: true,
    status: 200,
    headers: { get: (name) => name === "date" ? date : null },
    body: {
      getReader: () => ({
        read: async () => {
          if (read) return { done: true, value: undefined };
          read = true;
          response.ok = false;
          response.status = 500;
          date = "invalid";
          return { done: false, value: bytes };
        },
        cancel: async () => {},
      }),
    },
  };
  const stable = createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async () => response,
  });
  assert.equal((await stable.readWifAuditEvidenceObserved(wifObservedArguments(input))).observedAt,
    "2026-08-13T12:13:31.000Z");

  const marker = "ya29.hostile-google-token";
  const hostileResponses = [
    async () => { throw new Error(marker); },
    async () => ({
      ok: true,
      status: 200,
      get headers() { throw new Error(marker); },
    }),
    async () => ({
      ok: true,
      status: 200,
      headers: { get: (name) => name === "date" ? "Thu, 13 Aug 2026 12:13:31 GMT" : null },
      body: { getReader: () => { throw new Error(marker); } },
    }),
    async () => ({
      ok: true,
      status: 200,
      headers: { get: (name) => name === "date" ? "Thu, 13 Aug 2026 12:13:31 GMT" : null },
      body: { getReader: () => ({ read: async () => { throw new Error(marker); }, cancel: async () => {} }) },
    }),
  ];
  for (const fetchImpl of hostileResponses) {
    const reader = createGcpEvidenceReader({
      auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
      fetchImpl,
    });
    await assert.rejects(reader.readWifAuditEvidenceObserved(wifObservedArguments(input)), (error) => {
      assert.equal(error.message.includes(marker), false);
      return true;
    });
  }
  const hostileAuth = createGcpEvidenceReader({
    auth: { getClient: async () => { throw new Error(marker); } },
    fetchImpl: async () => { throw new Error("fetch must not run"); },
  });
  await assert.rejects(hostileAuth.readWifAuditEvidenceObserved(wifObservedArguments(input)), (error) => {
    assert.equal(error.message.includes(marker), false);
    return true;
  });
});

test("Cloud Run revision readback requires a resolved image digest", async () => {
  const reader = createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async (url) => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(url.includes("/revisions/") ? {
        name: "projects/keyless-k0-demo/locations/us-central1/services/keyless-demo/revisions/keyless-demo-wif-2",
        createTime: "2026-08-13T12:13:45Z",
        containers: [{ image: "us-docker.pkg.dev/example/app:latest", env: [{ name: "RELEASE", value: "wif-2" }] }],
      } : { latestReadyRevision: "keyless-demo-wif-2" }),
    }),
  });
  await assert.rejects(reader.readCloudRunRevision({
    projectId: "keyless-k0-demo", region: "us-central1", service: "keyless-demo",
  }), /image digest/);
});

test("Cloud Run revision readback rejects ambiguous containers", async () => {
  const reader = createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async (url) => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(url.includes("/revisions/") ? {
        name: "projects/keyless-k0-demo/locations/us-central1/services/keyless-demo/revisions/keyless-demo-wif-2",
        createTime: "2026-08-13T12:13:45Z",
        containers: [{
          image: `example/app@sha256:${"a".repeat(64)}`,
          env: [{ name: "RELEASE", value: "wif-2" }],
        }, { image: `example/sidecar@sha256:${"b".repeat(64)}` }],
      } : { latestReadyRevision: "keyless-demo-wif-2" }),
    }),
  });
  await assert.rejects(reader.readCloudRunRevision({
    projectId: "keyless-k0-demo", region: "us-central1", service: "keyless-demo",
  }), /ambiguous/);
});

test("GCP evidence reader binds key disable to one exact human Admin Activity entry", async () => {
  const keyResource = `projects/keyless-k0-demo/serviceAccounts/${plan.service_account}/keys/${"a".repeat(40)}`;
  const auditResource = `projects/-/serviceAccounts/110652672782847439596/keys/${"a".repeat(40)}`;
  const requests = [];
  const reader = createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      if (url.startsWith("https://iam.googleapis.com/v1/projects/-/serviceAccounts/")) {
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({
            email: plan.service_account,
            uniqueId: "110652672782847439596",
          }),
        };
      }
      assert.equal(url, "https://logging.googleapis.com/v2/entries:list");
      const body = JSON.parse(options.body);
      assert.match(body.filter, /DisableServiceAccountKey/);
      assert.match(body.filter, new RegExp(auditResource.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ entries: [{
          insertId: "audit-1",
          timestamp: "2026-08-13T12:01:00Z",
          protoPayload: {
            methodName: "google.iam.admin.v1.DisableServiceAccountKey",
            resourceName: auditResource,
            authenticationInfo: { principalEmail: "operator@example.com" },
            status: {},
          },
        }] }),
      };
    },
  });
  assert.deepEqual(await reader.readDisableAuditEntry({
    projectId: "keyless-k0-demo",
    projectNumber: plan.project_number,
    keyResource,
    humanActor: "operator@example.com",
    startTime: "2026-08-13T12:00:00Z",
    endTime: "2026-08-13T12:05:00Z",
  }), {
    method_name: "google.iam.admin.v1.DisableServiceAccountKey",
    resource_name: auditResource,
    key_id: "a".repeat(40),
    service_account_email: plan.service_account,
    service_account_unique_id: "110652672782847439596",
    project_id: "keyless-k0-demo",
    project_number: plan.project_number,
    principal_email: "operator@example.com",
    insert_id: "audit-1",
    timestamp: "2026-08-13T12:01:00Z",
    status: "SUCCEEDED",
  });
  const uniqueResource = `projects/-/serviceAccounts/110652672782847439596/keys/${"a".repeat(40)}`;
  const second = await reader.readDisableAuditEntry({
    projectId: "keyless-k0-demo",
    projectNumber: plan.project_number,
    keyResource: uniqueResource,
    humanActor: "operator@example.com",
    startTime: "2026-08-13T12:00:00.123456789Z",
    endTime: "2026-08-13T12:05:00.123456789Z",
  });
  assert.equal(second.service_account_email, plan.service_account);
  assert.equal(requests.length, 4);
});

test("GCP evidence reader rejects normalized-invalid calendar timestamps before I/O", async () => {
  const reader = createGcpEvidenceReader({
    auth: { getClient: async () => { throw new Error("must not authenticate"); } },
  });
  await assert.rejects(reader.readDisableAuditEntry({
    projectId: "keyless-k0-demo",
    projectNumber: plan.project_number,
    keyResource: `projects/keyless-k0-demo/serviceAccounts/${plan.service_account}/keys/${"a".repeat(40)}`,
    humanActor: "operator@example.com",
    startTime: "2026-02-29T12:00:00Z",
    endTime: "2026-03-01T12:00:00Z",
  }), /time/);
});

test("GCP evidence reader rejects an audit entry for a different numeric service account", async () => {
  const keyResource = `projects/keyless-k0-demo/serviceAccounts/${plan.service_account}/keys/${"a".repeat(40)}`;
  const reader = createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async (url) => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(url.startsWith("https://iam.googleapis.com/")
        ? { email: plan.service_account, uniqueId: "110652672782847439596" }
        : { entries: [{
          insertId: "audit-wrong-account",
          timestamp: "2026-08-13T12:01:00Z",
          protoPayload: {
            methodName: "google.iam.admin.v1.DisableServiceAccountKey",
            resourceName: `projects/-/serviceAccounts/999999999999999999999/keys/${"a".repeat(40)}`,
            authenticationInfo: { principalEmail: "operator@example.com" },
          },
        }] }),
    }),
  });
  await assert.rejects(reader.readDisableAuditEntry({
    projectId: "keyless-k0-demo",
    projectNumber: plan.project_number,
    keyResource,
    humanActor: "operator@example.com",
    startTime: "2026-08-13T12:00:00Z",
    endTime: "2026-08-13T12:05:00Z",
  }), /missing or ambiguous/);
});

test("GCP evidence reader rejects a failed disable Admin Activity entry", async () => {
  const keyResource = `projects/keyless-k0-demo/serviceAccounts/${plan.service_account}/keys/${"a".repeat(40)}`;
  const auditResource = `projects/-/serviceAccounts/110652672782847439596/keys/${"a".repeat(40)}`;
  const reader = createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async (url) => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(url.startsWith("https://iam.googleapis.com/")
        ? { email: plan.service_account, uniqueId: "110652672782847439596" }
        : { entries: [{
          insertId: "audit-failed",
          timestamp: "2026-08-13T12:01:00Z",
          protoPayload: {
            methodName: "google.iam.admin.v1.DisableServiceAccountKey",
            resourceName: auditResource,
            authenticationInfo: { principalEmail: "operator@example.com" },
            status: { code: 7, message: "permission denied" },
          },
        }] }),
    }),
  });
  await assert.rejects(reader.readDisableAuditEntry({
    projectId: "keyless-k0-demo",
    projectNumber: plan.project_number,
    keyResource,
    humanActor: "operator@example.com",
    startTime: "2026-08-13T12:00:00Z",
    endTime: "2026-08-13T12:05:00Z",
  }), /missing or ambiguous/);
});

test("GCP evidence reader rejects paginated key-disable audit results", async () => {
  const keyResource = `projects/keyless-k0-demo/serviceAccounts/${plan.service_account}/keys/${"a".repeat(40)}`;
  const reader = createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async (url) => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(url.startsWith("https://iam.googleapis.com/")
        ? { email: plan.service_account, uniqueId: "110652672782847439596" }
        : { entries: [], nextPageToken: "more" }),
    }),
  });
  await assert.rejects(reader.readDisableAuditEntry({
    projectId: "keyless-k0-demo",
    projectNumber: plan.project_number,
    keyResource,
    humanActor: "operator@example.com",
    startTime: "2026-08-13T12:00:00Z",
    endTime: "2026-08-13T12:05:00Z",
  }), /paginated/);
});

function disableObservedArguments(overrides = {}) {
  return {
    projectId: "keyless-k0-demo",
    projectNumber: plan.project_number,
    serviceAccountEmail: plan.service_account,
    serviceAccountUniqueId: "110652672782847439596",
    keyResource: `projects/keyless-k0-demo/serviceAccounts/${plan.service_account}/keys/${"a".repeat(40)}`,
    humanActor: "operator@example.com",
    startTime: "2026-08-13T12:00:00Z",
    endTime: "2026-08-13T12:05:00Z",
    ...overrides,
  };
}

function disableAuditResponse(overrides = {}) {
  return {
    entries: [{
      insertId: "audit-1",
      timestamp: "2026-08-13T12:01:00Z",
      protoPayload: {
        methodName: "google.iam.admin.v1.DisableServiceAccountKey",
        resourceName: `projects/-/serviceAccounts/110652672782847439596/keys/${"a".repeat(40)}`,
        authenticationInfo: { principalEmail: "operator@example.com" },
        status: {},
      },
    }],
    ...overrides,
  };
}

function disableObservedReader({ transform } = {}) {
  let index = 0;
  const bodies = [
    {
      name: `projects/${plan.project_id}/serviceAccounts/${plan.service_account}`,
      projectId: plan.project_id,
      email: plan.service_account,
      uniqueId: "110652672782847439596",
      // Real IAM v1 responses omit `disabled` for enabled accounts (proto3 default elision).
    },
    disableAuditResponse(),
  ];
  return createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async (url, options) => {
      const current = index;
      index += 1;
      const context = {
        index: current,
        url,
        options,
        value: structuredClone(bodies[current]),
        date: current === 0 ? "Thu, 13 Aug 2026 12:02:00 GMT" : "Thu, 13 Aug 2026 12:03:00 GMT",
      };
      const selected = transform?.(context) ?? context;
      return selected instanceof Response ? selected : observedJsonResponse(selected.value, { date: selected.date });
    },
  });
}

test("observed disable reader returns exact evidence and latest authenticated observation", async () => {
  const reader = disableObservedReader();
  const result = await reader.readDisableAuditEntryObserved(disableObservedArguments());
  assert.equal(result.observedAt, "2026-08-13T12:03:00.000Z");
  assert.deepEqual(result.evidence, {
    method_name: "google.iam.admin.v1.DisableServiceAccountKey",
    resource_name: `projects/-/serviceAccounts/110652672782847439596/keys/${"a".repeat(40)}`,
    key_id: "a".repeat(40),
    service_account_email: plan.service_account,
    service_account_unique_id: "110652672782847439596",
    project_id: "keyless-k0-demo",
    project_number: plan.project_number,
    principal_email: "operator@example.com",
    insert_id: "audit-1",
    timestamp: "2026-08-13T12:01:00Z",
    status: "SUCCEEDED",
  });
});

test("observed disable reader accepts only the four official scoped service-account names", async () => {
  const uniqueId = "110652672782847439596";
  for (const name of [
    `projects/${plan.project_id}/serviceAccounts/${plan.service_account}`,
    `projects/${plan.project_id}/serviceAccounts/${uniqueId}`,
    `projects/-/serviceAccounts/${plan.service_account}`,
    `projects/-/serviceAccounts/${uniqueId}`,
  ]) {
    const reader = disableObservedReader({
      transform: ({ index, ...context }) => index === 0
        ? { ...context, value: { ...context.value, name } }
        : context,
    });
    assert.equal((await reader.readDisableAuditEntryObserved(disableObservedArguments()))
      .evidence.service_account_unique_id, uniqueId);
  }
});

test("observed disable reader rejects missing or wrong service-account resource state", async () => {
  const attacks = [
    (account) => { account.email = "other@example.iam.gserviceaccount.com"; },
    (account) => { account.uniqueId = "999999999999999999999"; },
    (account) => { delete account.projectId; },
    (account) => { account.projectId = "other-project"; },
    (account) => { delete account.name; },
    (account) => { account.name = `projects/other-project/serviceAccounts/${account.email}`; },
    (account) => { account.name = `projects/${plan.project_id}/serviceAccounts/${encodeURIComponent(account.email)}`; },
    (account) => { account.name = `${account.name}/extra`; },
    (account) => { account.disabled = true; },
    (account) => { account.disabled = "false"; },
    (account) => { account.disabled = null; },
  ];
  for (const mutate of attacks) {
    const reader = disableObservedReader({
      transform: ({ index, ...context }) => {
        if (index === 0) mutate(context.value);
        return context;
      },
    });
    await assert.rejects(reader.readDisableAuditEntryObserved(disableObservedArguments()), /identity/);
  }
});

test("observed disable reader rejects filter-unsafe human actors before authentication", async () => {
  let authCalls = 0;
  let fetchCalls = 0;
  const reader = createGcpEvidenceReader({
    auth: { getClient: async () => { authCalls += 1; throw new Error("must not authenticate"); } },
    fetchImpl: async () => { fetchCalls += 1; throw new Error("must not fetch"); },
  });
  for (const humanActor of [
    "Operator@example.com",
    "operator@example",
    "operator..demo@example.com",
    "operator.@example.com",
    "operator\\@example.com",
    "operator\"@example.com",
    "operator@example.com\" OR true",
    "operator\n@example.com",
    "operator@example.com) OR (true",
  ]) {
    await assert.rejects(
      reader.readDisableAuditEntryObserved(disableObservedArguments({ humanActor })),
      /human actor/,
    );
  }
  await assert.rejects(reader.readDisableAuditEntryObserved(disableObservedArguments({
    serviceAccountEmail: "other@example.iam.gserviceaccount.com",
  })), /key resource/);
  await assert.rejects(reader.readDisableAuditEntryObserved(disableObservedArguments({
    serviceAccountUniqueId: "999999999999999999999",
    keyResource: `projects/keyless-k0-demo/serviceAccounts/110652672782847439596/keys/${"a".repeat(40)}`,
  })), /key resource/);
  assert.equal(authCalls, 0);
  assert.equal(fetchCalls, 0);
});

test("observed disable reader rejects identity, status, ambiguity, pagination, and time drift", async () => {
  const cases = [
    {
      transform: ({ index, ...context }) => index === 0
        ? { ...context, value: { email: "other@example.iam.gserviceaccount.com", uniqueId: "110652672782847439596" } }
        : context,
      pattern: /identity/,
    },
    {
      transform: ({ index, ...context }) => {
        if (index !== 1) return context;
        context.value.entries[0].protoPayload.status = { code: 7 };
        return context;
      },
      pattern: /missing or ambiguous/,
    },
    {
      transform: ({ index, ...context }) => index === 1
        ? { ...context, value: { entries: [...context.value.entries, structuredClone(context.value.entries[0])] } }
        : context,
      pattern: /missing or ambiguous/,
    },
    {
      transform: ({ index, ...context }) => index === 1
        ? { ...context, value: { ...context.value, nextPageToken: "more" } }
        : context,
      pattern: /paginated/,
    },
    {
      transform: ({ index, ...context }) => index === 1
        ? { ...context, date: "Thu, 13 Aug 2026 12:01:59 GMT" }
        : context,
      pattern: /regress/,
    },
    {
      transform: ({ index, ...context }) => {
        if (index !== 1) return { ...context, date: "Thu, 13 Aug 2026 12:00:30 GMT" };
        return { ...context, date: "Thu, 13 Aug 2026 12:00:59 GMT" };
      },
      pattern: /missing or ambiguous/,
    },
    {
      transform: ({ index, ...context }) => index === 1
        ? { ...context, date: null }
        : context,
      pattern: /Date/,
    },
  ];
  for (const { transform, pattern } of cases) {
    await assert.rejects(
      disableObservedReader({ transform }).readDisableAuditEntryObserved(disableObservedArguments()),
      pattern,
    );
  }
});
