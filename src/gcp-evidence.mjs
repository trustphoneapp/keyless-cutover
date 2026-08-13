import { createHash } from "node:crypto";
import { GoogleAuth } from "google-auth-library";

import { canonicalJson } from "./evidence-artifact.mjs";

const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const REGION = /^[a-z]+-[a-z]+\d$/;
const SERVICE = /^[a-z][a-z0-9-]{0,62}$/;
const SERVICE_ACCOUNT = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;
const PROVIDER = /^projects\/\d+\/locations\/global\/workloadIdentityPools\/[a-z0-9-]+\/providers\/[a-z0-9-]+$/;
const KEY_RESOURCE = /^projects\/[^/]+\/serviceAccounts\/[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com\/keys\/[a-f0-9]{40}$/;
const ACTOR = /^[^@\s]+@[^@\s]+$/;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

function exact(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function normalizedCondition(condition) {
  if (!condition) return null;
  return { title: condition.title ?? "", description: condition.description ?? "", expression: condition.expression ?? "" };
}

export function normalizeIamPolicy(policy) {
  const bindings = (policy?.bindings ?? []).flatMap((binding) => (binding.members ?? []).map((member) => ({
    role: binding.role,
    member,
    condition: normalizedCondition(binding.condition),
  }))).sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  return { version: policy?.version ?? 1, bindings };
}

function normalizedProvider(provider) {
  return {
    name: provider.name,
    issuer: provider.oidc?.issuerUri,
    allowed_audiences: [...(provider.oidc?.allowedAudiences ?? [])].sort(),
    attribute_mapping: provider.attributeMapping ?? {},
    attribute_condition: provider.attributeCondition ?? "",
  };
}

function policySet(policy) {
  return new Set(normalizeIamPolicy(policy).bindings.map((binding) => canonicalJson(binding).trim()));
}

function setDifference(left, right) {
  return [...left].filter((value) => !right.has(value)).sort();
}

export function verifyWifReadback({
  plan,
  provider,
  serviceAccountPolicyBefore,
  serviceAccountPolicyAfter,
  allowedPolicyBefore,
  allowedPolicyAfter,
  forbiddenPolicyBefore,
  forbiddenPolicyAfter,
}) {
  const providerConfig = normalizedProvider(provider);
  if (provider.name !== plan.provider || provider.state !== "ACTIVE"
      || digest(canonicalJson(providerConfig)) !== plan.provider_config_hash) {
    throw new Error("live WIF provider does not match the approved plan");
  }
  const before = policySet(serviceAccountPolicyBefore);
  const after = policySet(serviceAccountPolicyAfter);
  const added = setDifference(after, before);
  const removed = setDifference(before, after);
  const expected = canonicalJson({
    role: plan.impersonation_binding.role,
    member: plan.impersonation_binding.member,
    condition: null,
  }).trim();
  if (added.length !== 1 || added[0] !== expected || removed.length !== 0) {
    throw new Error("service-account IAM delta is not the exact approved binding");
  }
  const allowedBeforeHash = digest(canonicalJson(normalizeIamPolicy(allowedPolicyBefore)));
  const allowedAfterHash = digest(canonicalJson(normalizeIamPolicy(allowedPolicyAfter)));
  const forbiddenBeforeHash = digest(canonicalJson(normalizeIamPolicy(forbiddenPolicyBefore)));
  const forbiddenAfterHash = digest(canonicalJson(normalizeIamPolicy(forbiddenPolicyAfter)));
  if (allowedBeforeHash !== allowedAfterHash || forbiddenBeforeHash !== forbiddenAfterHash) {
    throw new Error("downstream Cloud Run IAM policy changed during cutover");
  }
  const delta = {
    added,
    removed,
    allowed_policy_before: allowedBeforeHash,
    allowed_policy_after: allowedAfterHash,
    forbidden_policy_before: forbiddenBeforeHash,
    forbidden_policy_after: forbiddenAfterHash,
  };
  return {
    provider: { name: provider.name, config_hash: plan.provider_config_hash, state: provider.state },
    policy: {
      policy_hash: digest(canonicalJson(normalizeIamPolicy(serviceAccountPolicyAfter))),
      iam_diff_hash: digest(canonicalJson(delta)),
      etag: serviceAccountPolicyAfter.etag,
      no_added_downstream_permissions: true,
    },
  };
}

export function createGcpEvidenceReader({
  auth = new GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform.read-only"] }),
  fetchImpl = fetch,
} = {}) {
  const request = async (method, url, body) => {
    const client = await auth.getClient();
    const authHeaders = await client.getRequestHeaders(url);
    const headers = new Headers(authHeaders);
    headers.set("content-type", "application/json");
    const response = await fetchImpl(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(8_000),
    });
    const text = await response.text();
    if (text.length > 1_000_000) throw new Error("Google API response is too large");
    if (!response.ok) throw new Error(`Google API ${method} failed with HTTP ${response.status}`);
    return JSON.parse(text);
  };
  return {
    async readCloudRunRevision({ projectId, region, service }) {
      exact(projectId, PROJECT_ID, "project ID");
      exact(region, REGION, "region");
      exact(service, SERVICE, "service");
      const value = await request("GET", `https://run.googleapis.com/v2/projects/${projectId}/locations/${region}/services/${service}`);
      const revision = value.latestReadyRevision?.split("/").at(-1);
      if (!exact(revision, SERVICE, "latest ready revision")) throw new Error("Cloud Run service has no valid latest ready revision");
      return { service, revision };
    },
    async readCloudRunIamPolicy({ projectId, region, service }) {
      exact(projectId, PROJECT_ID, "project ID");
      exact(region, REGION, "region");
      exact(service, SERVICE, "service");
      return request("GET", `https://run.googleapis.com/v2/projects/${projectId}/locations/${region}/services/${service}:getIamPolicy`);
    },
    async readWifProvider({ provider }) {
      exact(provider, PROVIDER, "provider");
      return request("GET", `https://iam.googleapis.com/v1/${provider}`);
    },
    async readServiceAccountPolicy({ serviceAccount }) {
      exact(serviceAccount, SERVICE_ACCOUNT, "service account");
      return request(
        "POST",
        `https://iam.googleapis.com/v1/projects/-/serviceAccounts/${encodeURIComponent(serviceAccount)}:getIamPolicy`,
        { options: { requestedPolicyVersion: 3 } },
      );
    },
    async readDisableAuditEntry({ projectId, keyResource, humanActor, startTime, endTime }) {
      exact(projectId, PROJECT_ID, "project ID");
      exact(keyResource, KEY_RESOURCE, "key resource");
      exact(humanActor, ACTOR, "human actor");
      exact(startTime, ISO_TIME, "start time");
      exact(endTime, ISO_TIME, "end time");
      const start = Date.parse(startTime);
      const end = Date.parse(endTime);
      if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start || end - start > 24 * 60 * 60 * 1000) {
        throw new Error("audit time window is invalid");
      }
      const method = "google.iam.admin.v1.DisableServiceAccountKey";
      const value = await request("POST", "https://logging.googleapis.com/v2/entries:list", {
        resourceNames: [`projects/${projectId}`],
        filter: [
          `protoPayload.methodName=\"${method}\"`,
          `protoPayload.resourceName=\"${keyResource}\"`,
          `protoPayload.authenticationInfo.principalEmail=\"${humanActor}\"`,
          `timestamp>=\"${startTime}\"`,
          `timestamp<=\"${endTime}\"`,
        ].join(" AND "),
        orderBy: "timestamp desc",
        pageSize: 10,
      });
      const matches = (value.entries ?? []).filter((entry) => entry?.protoPayload?.methodName === method
        && entry.protoPayload.resourceName === keyResource
        && entry.protoPayload.authenticationInfo?.principalEmail === humanActor
        && (!entry.protoPayload.status || entry.protoPayload.status.code === 0)
        && Date.parse(entry.timestamp) >= start && Date.parse(entry.timestamp) <= end);
      if (matches.length !== 1 || typeof matches[0].insertId !== "string") {
        throw new Error("exact human key-disable audit entry is missing or ambiguous");
      }
      return {
        method_name: method,
        resource_name: keyResource,
        principal_email: humanActor,
        insert_id: matches[0].insertId,
        timestamp: matches[0].timestamp,
      };
    },
  };
}
