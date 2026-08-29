import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { parseWifAuditEvidence } from "../src/k0-evidence-normalizer.mjs";
import { canonicalJson } from "../src/evidence-artifact.mjs";

// These tests run the parser against the exact Cloud Audit Log bytes Google wrote for this project's
// own live transactions, recorded under docs/evidence/forensics/. They exist because the parser was
// originally pinned to Google's published example shapes, which differ from what Google actually
// logs: the STS request carries the full parameter set, its metadata carries an @type, and a
// federated GenerateAccessToken is attributed by principalEmail rather than principalSubject. Every
// shape the parser now accepts is pinned to a value below, so a real recording passing here is not
// evidence that a forged one would.

const forensics = (name) => JSON.parse(readFileSync(
  fileURLToPath(new URL(`../docs/evidence/forensics/${name}`, import.meta.url)),
  "utf8",
));

const PROJECTED_PAYLOAD_FIELDS = [
  "@type", "authenticationInfo", "metadata", "methodName", "request", "resourceName", "serviceName", "status",
];

// Mirrors projectWifAuditEvidence: keep only the projected payload fields and strip the issued token.
function project(entry) {
  const payload = entry.protoPayload;
  const protoPayload = Object.fromEntries(
    Object.entries(payload).filter(([key]) => PROJECTED_PAYLOAD_FIELDS.includes(key)),
  );
  if (payload.authenticationInfo && typeof payload.authenticationInfo === "object") {
    const { loggableShortLivedCredential: _issued, ...rest } = payload.authenticationInfo;
    protoPayload.authenticationInfo = rest;
  }
  return { insertId: entry.insertId, timestamp: entry.timestamp, protoPayload, resource: entry.resource };
}

function pairBytes(sts, iam) {
  return Buffer.from(canonicalJson({ entries: [project(sts), project(iam)] }));
}

function realPair() {
  const all = forensics("all-wif-audit-entries.json");
  const sts = all.find((entry) => (entry.protoPayload?.methodName ?? "").includes("ExchangeToken")
    && entry.protoPayload?.metadata?.mapped_principal);
  const exchangedAt = Date.parse(sts.timestamp);
  const iam = all
    .filter((entry) => entry.protoPayload?.methodName === "GenerateAccessToken"
      && entry.protoPayload?.authenticationInfo?.principalEmail?.startsWith("keyless-deploy@")
      && Date.parse(entry.timestamp) >= exchangedAt
      && Date.parse(entry.timestamp) - exchangedAt < 600_000)
    .sort((left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp))[0];
  return { sts, iam };
}

test("parser accepts every genuine federated exchange this project has recorded", () => {
  const all = forensics("all-wif-audit-entries.json");
  const exchanges = all.filter((entry) => (entry.protoPayload?.methodName ?? "").includes("ExchangeToken")
    && entry.protoPayload?.metadata?.mapped_principal);
  const grants = all.filter((entry) => entry.protoPayload?.methodName === "GenerateAccessToken"
    && entry.protoPayload?.authenticationInfo?.principalEmail?.startsWith("keyless-deploy@"));
  assert.ok(exchanges.length >= 10, "recorded successful exchanges are missing");

  let accepted = 0;
  for (const sts of exchanges) {
    const exchangedAt = Date.parse(sts.timestamp);
    const iam = grants
      .filter((entry) => Date.parse(entry.timestamp) >= exchangedAt
        && Date.parse(entry.timestamp) - exchangedAt < 600_000)
      .sort((left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp))[0];
    if (!iam) continue;
    const claims = parseWifAuditEvidence(pairBytes(sts, iam));
    assert.equal(claims.service_account_email, iam.protoPayload.authenticationInfo.principalEmail);
    assert.match(claims.idp_subject, /^repo:[^@]+@\d+\/[^@]+@\d+:environment:production$/);
    accepted += 1;
  }
  assert.ok(accepted >= 10, `expected every recorded pair to parse, accepted ${accepted}`);
});

test("parser rejects a forged or mismatched audit pair built from real bytes", () => {
  const { sts, iam } = realPair();
  assert.doesNotThrow(() => parseWifAuditEvidence(pairBytes(sts, iam)));

  const forge = (mutate) => {
    const pair = JSON.parse(canonicalJson({ entries: [project(sts), project(iam)] }));
    mutate(pair);
    return () => parseWifAuditEvidence(Buffer.from(canonicalJson(pair)));
  };

  // The relaxed STS request shape is paid for by pinning every one of its values.
  assert.throws(forge((pair) => {
    pair.entries[0].protoPayload.request.audience = "//iam.googleapis.com/projects/9/locations/global/workloadIdentityPools/evil/providers/x";
  }), /WIF audit identity is invalid/);
  assert.throws(forge((pair) => {
    pair.entries[0].protoPayload.request.subjectTokenType = "urn:ietf:params:oauth:token-type:saml2";
  }), /WIF audit identity is invalid/);
  assert.throws(forge((pair) => {
    pair.entries[0].protoPayload.request.smuggled = "x";
  }), /WIF audit identity is invalid/);
  assert.throws(forge((pair) => {
    pair.entries[0].protoPayload.metadata["@type"] = "type.googleapis.com/forged.AuditData";
  }), /WIF audit identity is invalid/);

  // The IAM entry no longer carries principalSubject, so its principalEmail is bound instead.
  assert.throws(forge((pair) => {
    pair.entries[1].protoPayload.authenticationInfo.principalEmail = "attacker@keyless-k0-20260813.iam.gserviceaccount.com";
  }), /WIF audit identity is invalid/);
  assert.throws(forge((pair) => {
    delete pair.entries[1].protoPayload.authenticationInfo.principalEmail;
  }), /WIF audit identity is invalid/);
  assert.throws(forge((pair) => {
    pair.entries[1].protoPayload.authenticationInfo.principalSubject = "principal://iam.googleapis.com/projects/9/x";
  }), /WIF audit identity is invalid/);

  // The STS entry must still prove the federated subject itself.
  assert.throws(forge((pair) => {
    delete pair.entries[0].protoPayload.authenticationInfo.principalSubject;
  }), /WIF audit identity is invalid/);
  assert.throws(forge((pair) => {
    pair.entries[0].protoPayload.metadata.mapped_principal = "principal://iam.googleapis.com/projects/9/locations/global/workloadIdentityPools/evil/subject/repo:x";
  }), /WIF audit identity is invalid/);
});

test("parser rejects an operator-initiated token grant substituted for the deploy identity", () => {
  const all = forensics("all-wif-audit-entries.json");
  const { sts, iam } = realPair();
  const operatorGrant = all.find((entry) => entry.protoPayload?.methodName === "GenerateAccessToken"
    && entry.protoPayload?.authenticationInfo?.principalEmail
    && !entry.protoPayload.authenticationInfo.principalEmail.startsWith("keyless-deploy@"));
  assert.ok(operatorGrant, "a non-deploy grant is required for this test");
  assert.doesNotThrow(() => parseWifAuditEvidence(pairBytes(sts, iam)));
  assert.throws(() => parseWifAuditEvidence(pairBytes(sts, operatorGrant)), /WIF audit identity is invalid/);
});
