import assert from "node:assert/strict";
import test from "node:test";

import {
  normalizeCloudRunObservation,
  normalizeGoogleKeyEvidence,
  parseWifAuditEvidence,
} from "../src/k0-evidence-normalizer.mjs";
import { canonicalJson } from "../src/evidence-artifact.mjs";
import { validK0BundleInput, validWifAuditLog } from "./fixtures/k0-bundle.mjs";

test("WIF parser accepts only the bounded documented STS and IAM audit variants", () => {
  const input = validK0BundleInput();
  const auditLog = validWifAuditLog(input.manifest);
  const parsed = parseWifAuditEvidence(auditLog);
  assert.equal(parsed.idp_subject, input.manifest.wif.idp_subject);
  assert.equal(parsed.mapped_principal, input.manifest.wif.mapped_principal);
  assert.notEqual(parsed.idp_subject, parsed.mapped_principal);
  assert.equal(parsed.provider, input.manifest.wif.provider);
  assert.equal("run_id" in parsed, false);
  assert.deepEqual(JSON.parse(auditLog).entries[0].protoPayload.request, {
    "@type": "type.googleapis.com/google.identity.sts.v1.ExchangeTokenRequest",
    audience: `//iam.googleapis.com/${input.manifest.wif.provider}`,
    grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
    requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
    subjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
  });

  const documentedLong = JSON.parse(auditLog);
  documentedLong.entries[0].protoPayload.serviceName = "sts.googleapis.com";
  documentedLong.entries[0].protoPayload.status = {};
  documentedLong.entries[1].protoPayload.methodName = "google.iam.credentials.v1.IAMCredentials.GenerateAccessToken";
  documentedLong.entries[1].protoPayload.resourceName = documentedLong.entries[1].protoPayload.request.name;
  documentedLong.entries[1].protoPayload.serviceName = "iamcredentials.googleapis.com";
  documentedLong.entries[1].protoPayload.status = {};
  assert.equal(parseWifAuditEvidence(Buffer.from(canonicalJson(documentedLong))).mapped_principal,
    input.manifest.wif.mapped_principal);

  assert.throws(() => parseWifAuditEvidence(Buffer.from("arbitrary text")), /JSON/);
  for (const mutate of [
    (value) => { value.extra = true; },
    (value) => { value.entries = [value.entries[0], structuredClone(value.entries[0])]; },
    (value) => { value.entries[0].protoPayload.methodName = "wrong"; },
    (value) => { value.entries[0].protoPayload.request.grantType = "wrong"; },
    (value) => { value.entries[1].protoPayload.status = { code: 7 }; },
    (value) => { value.entries[1].protoPayload.authenticationInfo.principalSubject = "wrong"; },
    (value) => {
      const wrong = "principal://iam.googleapis.com/projects/9/locations/global/workloadIdentityPools/wrong/subject/repo:wrong/wrong";
      value.entries[0].protoPayload.metadata.mapped_principal = wrong;
      value.entries[1].protoPayload.authenticationInfo.principalSubject = wrong;
    },
    (value) => { value.entries[1].timestamp = "2026-08-13T12:23:20.000000001Z"; },
  ]) {
    const changed = JSON.parse(auditLog);
    mutate(changed);
    assert.throws(() => parseWifAuditEvidence(Buffer.from(canonicalJson(changed))), /audit/i);
  }
});

test("WIF parser rejects extra and token-bearing STS request fields", () => {
  const auditLog = validWifAuditLog(validK0BundleInput().manifest);
  for (const field of ["extra", "subject_token", "actor_token"]) {
    const changed = JSON.parse(auditLog);
    changed.entries[0].protoPayload.request[field] = "forbidden";
    assert.throws(() => parseWifAuditEvidence(Buffer.from(canonicalJson(changed))), /audit/i);
  }
});

test("GCP normalizers emit exact scoped revision and key shapes", () => {
  assert.deepEqual(normalizeCloudRunObservation({
    project_id: "example-project",
    region: "us-central1",
    service: "keyless-demo",
    revision: "keyless-demo-wif-2",
    create_time: "2026-08-13T12:13:45Z",
    release_marker: "wif-2",
    image_digest: `sha256:${"a".repeat(64)}`,
  }), {
    project_id: "example-project",
    region: "us-central1",
    service: "keyless-demo",
    revision: "keyless-demo-wif-2",
    create_time: "2026-08-13T12:13:45Z",
    release_marker: "wif-2",
    image_digest: `sha256:${"a".repeat(64)}`,
  });
  const scope = {
    project_id: "example-project",
    project_number: "3",
    service_account_email: "deploy@example.iam.gserviceaccount.com",
    service_account_unique_id: "110652672782847439596",
  };
  const key = normalizeGoogleKeyEvidence({
    key: {
      name: `projects/example-project/serviceAccounts/${scope.service_account_email}/keys/${"a".repeat(40)}`,
      keyType: "USER_MANAGED",
      keyAlgorithm: "KEY_ALG_RSA_2048",
      disabled: true,
    },
    scope,
  });
  assert.equal(key.project_id, scope.project_id);
  assert.equal(key.key_id, "a".repeat(40));
});
