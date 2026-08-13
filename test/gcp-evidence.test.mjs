import assert from "node:assert/strict";
import test from "node:test";

import { createGcpEvidenceReader, verifyWifReadback } from "../src/gcp-evidence.mjs";
import { buildWifPlan } from "../src/wif-plan.mjs";

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

test("GCP readback proves exact WIF trust addition and unchanged downstream IAM", () => {
  const result = verifyWifReadback({
    plan,
    provider,
    serviceAccountPolicyBefore: serviceAccountBefore,
    serviceAccountPolicyAfter: serviceAccountAfter,
    allowedPolicyBefore: downstream,
    allowedPolicyAfter: structuredClone(downstream),
    forbiddenPolicyBefore: { version: 3, etag: "f1", bindings: [] },
    forbiddenPolicyAfter: { version: 3, etag: "f2", bindings: [] },
  });
  assert.deepEqual(result.provider, { name: plan.provider, config_hash: plan.provider_config_hash, state: "ACTIVE" });
  assert.equal(result.policy.no_added_downstream_permissions, true);
  assert.match(result.policy.iam_diff_hash, /^[a-f0-9]{64}$/);
  assert.throws(() => verifyWifReadback({
    plan,
    provider,
    serviceAccountPolicyBefore: serviceAccountBefore,
    serviceAccountPolicyAfter: serviceAccountAfter,
    allowedPolicyBefore: downstream,
    allowedPolicyAfter: { ...downstream, bindings: [] },
    forbiddenPolicyBefore: downstream,
    forbiddenPolicyAfter: downstream,
  }), /downstream/);
});

test("GCP evidence reader uses ADC and normalizes the latest ready revision", async () => {
  const requests = [];
  const reader = createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          latestReadyRevision: "projects/keyless-k0-demo/locations/us-central1/services/keyless-demo/revisions/keyless-demo-wif-2",
        }),
      };
    },
  });
  assert.deepEqual(await reader.readCloudRunRevision({
    projectId: "keyless-k0-demo", region: "us-central1", service: "keyless-demo",
  }), { service: "keyless-demo", revision: "keyless-demo-wif-2" });
  assert.equal(requests[0].options.headers.authorization, "Bearer test");
});

test("GCP evidence reader binds key disable to one exact human Admin Activity entry", async () => {
  const keyResource = `projects/keyless-k0-demo/serviceAccounts/${plan.service_account}/keys/${"a".repeat(40)}`;
  const reader = createGcpEvidenceReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async (url, options) => {
      assert.equal(url, "https://logging.googleapis.com/v2/entries:list");
      const body = JSON.parse(options.body);
      assert.match(body.filter, /DisableServiceAccountKey/);
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ entries: [{
          insertId: "audit-1",
          timestamp: "2026-08-13T12:01:00Z",
          protoPayload: {
            methodName: "google.iam.admin.v1.DisableServiceAccountKey",
            resourceName: keyResource,
            authenticationInfo: { principalEmail: "operator@example.com" },
          },
        }] }),
      };
    },
  });
  assert.deepEqual(await reader.readDisableAuditEntry({
    projectId: "keyless-k0-demo",
    keyResource,
    humanActor: "operator@example.com",
    startTime: "2026-08-13T12:00:00Z",
    endTime: "2026-08-13T12:05:00Z",
  }), {
    method_name: "google.iam.admin.v1.DisableServiceAccountKey",
    resource_name: keyResource,
    principal_email: "operator@example.com",
    insert_id: "audit-1",
    timestamp: "2026-08-13T12:01:00Z",
  });
});
