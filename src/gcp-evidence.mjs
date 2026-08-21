import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";
import { canonicalJson, decodeUtf8 } from "./evidence-artifact.mjs";
import { parseWifAuditEvidence } from "./k0-evidence-normalizer.mjs";
import { parseAuthenticatedTransportObservation, rejectDuplicateJsonKeys } from "./observation-time.mjs";
import { isRfc3339, timestampNanoseconds } from "./rfc3339.mjs";
import { buildWifPlan } from "./wif-plan.mjs";

const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const REGION = /^[a-z]+-[a-z]+\d$/;
const SERVICE = /^[a-z][a-z0-9-]{0,62}$/;
const SERVICE_ACCOUNT = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;
const PROVIDER = /^projects\/\d+\/locations\/global\/workloadIdentityPools\/[a-z0-9-]+\/providers\/[a-z0-9-]+$/;
const PROVIDER_PARTS = /^projects\/(\d+)\/locations\/global\/workloadIdentityPools\/([a-z0-9-]+)\/providers\/([a-z0-9-]+)$/;
const KEY_RESOURCE = /^projects\/(-|[a-z][a-z0-9-]{4,28}[a-z0-9])\/serviceAccounts\/([a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com|\d{10,30})\/keys\/([a-f0-9]{40})$/;
const UNIQUE_ID = /^\d{10,30}$/;
const ACTOR = /^[^@\s]+@[^@\s]+$/;
const HUMAN_ACTOR = /^(?=.{3,254}$)(?=[^@]{1,64}@)[a-z0-9](?:[a-z0-9_+-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_+-]*[a-z0-9])?)*@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const STS_REQUEST_FIELDS = new Set(["@type", "grantType"]);
const POLICY_FIELDS = new Set(["version", "etag", "bindings"]);
const BINDING_FIELDS = new Set(["role", "members", "condition"]);
const CONDITION_FIELDS = new Set(["title", "description", "expression"]);
const PROVIDER_FIELDS = new Set([
  "name", "displayName", "description", "state", "disabled", "attributeMapping", "attributeCondition",
  "expireTime", "oidc",
]);
const OIDC_FIELDS = new Set(["issuerUri", "allowedAudiences", "jwksJson"]);
const MAX_PARITY_RESPONSE = 1_000_000;
const PARITY_PLAN_FIELDS = new Set([
  "version", "project_id", "project_number", "issuer", "pool_id", "provider_id", "provider", "audience",
  "service_account", "workflow_ref", "attribute_mapping", "attribute_condition", "provider_config_hash",
  "impersonation_binding", "impersonation_binding_hash", "commands", "plan_digest", "allowed_service", "forbidden_service",
]);
const PARITY_SCOPE_FIELDS = new Set([
  "owner_id", "repository_id", "workflow_path", "proof_workflow_path", "legacy_workflow_path",
  "h1_workflow_path", "h2_workflow_path", "h4_workflow_path", "project_id", "project_number", "region",
  "service_account_email", "service_account_unique_id", "key_id", "allowed_service", "forbidden_service",
]);
const EXACT_REVISION_FIELDS = new Set([
  "projectId", "region", "service", "revision", "expectedReleaseMarker", "expectedCreateTime", "expectedImageDigest",
]);
const CANONICAL_RESOURCE_ID = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const IMMUTABLE_REVISION = /^(?!latest$)[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function exact(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function exactObject(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === fields.size
    && Object.keys(value).every((key) => fields.has(key));
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function immutableImageDigest(value) {
  if (typeof value !== "string" || value.length > 327
      || value.indexOf("@") < 0 || value.indexOf("@") !== value.lastIndexOf("@")) return undefined;
  const [name, imageDigest] = value.split("@");
  if (name.length > 255 || !/^sha256:[a-f0-9]{64}$/.test(imageDigest)) return undefined;
  const [registry, ...path] = name.split("/");
  const labels = registry.split(".");
  if (registry.length > 253 || labels.some((label) => label.length < 1 || label.length > 63
      || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) return undefined;
  // OCI component := alnum+ (("." | "_" | "__" | "-"+) alnum+)*.
  // This contract bounds the full repository name, including registry and slashes, to 255 bytes.
  if (path.length < 1 || path.some((component) => component.length < 1
      || !/^[a-z0-9]+(?:(?:\.|_{1,2}|-+)[a-z0-9]+)*$/.test(component))) return undefined;
  return imageDigest;
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

function strictProvider(provider, name) {
  if (!provider || typeof provider !== "object" || Array.isArray(provider)
      || Object.getPrototypeOf(provider) !== Object.prototype
      || Object.keys(provider).some((field) => !PROVIDER_FIELDS.has(field))
      || !Object.hasOwn(provider, "name") || !Object.hasOwn(provider, "state")
      || !Object.hasOwn(provider, "attributeMapping") || !Object.hasOwn(provider, "attributeCondition")
      || !Object.hasOwn(provider, "oidc") || provider.state !== "ACTIVE"
      || (Object.hasOwn(provider, "disabled") && provider.disabled !== false)
      || !provider.attributeMapping || typeof provider.attributeMapping !== "object"
      || Array.isArray(provider.attributeMapping) || Object.getPrototypeOf(provider.attributeMapping) !== Object.prototype
      || Object.keys(provider.attributeMapping).length > 50
      || Object.entries(provider.attributeMapping).some(([key, value]) => !key || key.length > 256
        || typeof value !== "string" || !value || value.length > 2048 || /[\r\n]/.test(key + value))
      || typeof provider.attributeCondition !== "string" || !provider.attributeCondition
      || provider.attributeCondition.length > 4096 || /[\r\n]/.test(provider.attributeCondition)
      || !provider.oidc || typeof provider.oidc !== "object" || Array.isArray(provider.oidc)
      || Object.getPrototypeOf(provider.oidc) !== Object.prototype
      || Object.keys(provider.oidc).some((field) => !OIDC_FIELDS.has(field))
      || typeof provider.oidc.issuerUri !== "string" || !provider.oidc.issuerUri
      || !Array.isArray(provider.oidc.allowedAudiences ?? [])
      || (provider.oidc.allowedAudiences ?? []).length > 10
      || (provider.oidc.allowedAudiences ?? []).some((audience) => typeof audience !== "string"
        || !audience || audience.length > 2048 || /[\r\n]/.test(audience))
      || (Object.hasOwn(provider.oidc, "jwksJson") && provider.oidc.jwksJson !== "")
      || (Object.hasOwn(provider, "displayName")
        && (typeof provider.displayName !== "string" || provider.displayName.length > 2048 || /[\r\n]/.test(provider.displayName)))
      || (Object.hasOwn(provider, "description")
        && (typeof provider.description !== "string" || provider.description.length > 2048 || /[\r\n]/.test(provider.description)))
      || (Object.hasOwn(provider, "expireTime") && !isRfc3339(provider.expireTime))) {
    throw new Error(`${name} is invalid`);
  }
  const snapshot = {
    name: provider.name,
    ...(Object.hasOwn(provider, "displayName") ? { displayName: provider.displayName } : {}),
    ...(Object.hasOwn(provider, "description") ? { description: provider.description } : {}),
    state: provider.state,
    disabled: provider.disabled ?? false,
    attributeMapping: Object.fromEntries(Object.entries(provider.attributeMapping)),
    attributeCondition: provider.attributeCondition,
    ...(Object.hasOwn(provider, "expireTime") ? { expireTime: provider.expireTime } : {}),
    oidc: {
      issuerUri: provider.oidc.issuerUri,
      allowedAudiences: [...(provider.oidc.allowedAudiences ?? [])],
    },
  };
  return { snapshot, config: normalizedProvider(snapshot) };
}

function policySet(policy) {
  return new Set(normalizeIamPolicy(policy).bindings.map((binding) => canonicalJson(binding).trim()));
}

function setDifference(left, right) {
  return [...left].filter((value) => !right.has(value)).sort();
}

function validEtag(value) {
  if (typeof value !== "string" || !value || value.length > 512
      || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) return false;
  try {
    canonicalJson(value);
    return true;
  } catch {
    return false;
  }
}

function strictPolicy(policy, name) {
  if (!exactObject(policy, POLICY_FIELDS) || !Number.isInteger(policy.version)
      || ![1, 3].includes(policy.version) || !validEtag(policy.etag)
      || !Array.isArray(policy.bindings) || policy.bindings.length > 100) {
    throw new Error(`${name} is invalid`);
  }
  for (const binding of policy.bindings) {
    const fields = binding && typeof binding === "object" && !Array.isArray(binding)
      ? new Set(Object.keys(binding)) : null;
    if (!fields || ![2, 3].includes(fields.size)
        || [...fields].some((field) => !BINDING_FIELDS.has(field))
        || typeof binding.role !== "string" || !/^roles\/[A-Za-z0-9_.]+$/.test(binding.role)
        || !Array.isArray(binding.members) || !binding.members.length || binding.members.length > 100
        || binding.members.some((member) => typeof member !== "string" || !member
          || member.length > 2048 || /[\r\n]/.test(member))) {
      throw new Error(`${name} is invalid`);
    }
    if (Object.hasOwn(binding, "condition")
        && (!exactObject(binding.condition, CONDITION_FIELDS)
          || Object.values(binding.condition).some((value) => typeof value !== "string" || value.length > 2048))) {
      throw new Error(`${name} is invalid`);
    }
  }
  const normalized = normalizeIamPolicy(policy);
  const entries = normalized.bindings.map((binding) => canonicalJson(binding));
  if (new Set(entries).size !== entries.length) throw new Error(`${name} contains duplicate IAM grants`);
  return { normalized, hash: digest(canonicalJson(normalized)), etag: policy.etag };
}

function isWifMember(member) {
  return typeof member === "string"
    && (member.startsWith("principal://") || member.startsWith("principalSet://")
      || member.includes("/workloadIdentityPools/"));
}

function parityDigest(value) {
  return createHash("sha256")
    .update("KEYLESS_GCP_WIF_PARITY_V1\0")
    .update(canonicalJson(value))
    .digest("hex");
}

function etagDigest(value) {
  return createHash("sha256")
    .update("KEYLESS_GCP_IAM_ETAG_V1\0")
    .update(value, "utf8")
    .digest("hex");
}

function snapshotPlainJson(value, name) {
  const seen = new Set();
  const visit = (current) => {
    if (current === null || typeof current === "string" || typeof current === "boolean"
        || (typeof current === "number" && Number.isFinite(current))) return;
    if (!current || typeof current !== "object" || utilTypes.isProxy(current) || seen.has(current)) {
      throw new Error(`${name} is invalid`);
    }
    seen.add(current);
    let prototype;
    let descriptors;
    try {
      prototype = Object.getPrototypeOf(current);
      descriptors = Object.getOwnPropertyDescriptors(current);
    } catch {
      throw new Error(`${name} is invalid`);
    }
    const array = Array.isArray(current);
    if (prototype !== (array ? Array.prototype : Object.prototype)) throw new Error(`${name} is invalid`);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== "string")) throw new Error(`${name} is invalid`);
    if (array) {
      if (keys.length !== current.length + 1 || !Object.hasOwn(descriptors, "length")) {
        throw new Error(`${name} is invalid`);
      }
      for (let index = 0; index < current.length; index += 1) {
        if (!Object.hasOwn(descriptors, String(index))) throw new Error(`${name} is invalid`);
      }
    }
    for (const key of keys) {
      if (array && key === "length") continue;
      const descriptor = descriptors[key];
      if (!("value" in descriptor) || descriptor.enumerable !== true) throw new Error(`${name} is invalid`);
      visit(descriptor.value);
    }
  };
  visit(value);
  try {
    return JSON.parse(canonicalJson(value));
  } catch {
    throw new Error(`${name} is invalid`);
  }
}

function validateApprovedParityPlan(plan) {
  const provider = PROVIDER_PARTS.exec(plan.provider ?? "");
  const workflow = /^([^/]+)\/([^/]+)\/\.github\/workflows\/k0-deploy\.yml@refs\/heads\/main$/.exec(plan.workflow_ref ?? "");
  const ownerId = plan.attribute_condition?.match(/(?:^| && )assertion\.repository_owner_id=='(\d+)'(?: && |$)/)?.[1];
  const repositoryId = plan.impersonation_binding?.member?.match(/\/attribute\.repo_id\/(\d+)$/)?.[1];
  if (!provider || !workflow || !ownerId || !repositoryId) throw new Error("approved WIF parity plan is invalid");
  let rebuilt;
  try {
    rebuilt = buildWifPlan({
      project_id: plan.project_id,
      project_number: provider[1],
      pool_id: provider[2],
      provider_id: provider[3],
      owner_id: ownerId,
      repository_id: repositoryId,
      owner: workflow[1],
      repository: workflow[2],
      service_account: plan.service_account,
    });
  } catch {
    throw new Error("approved WIF parity plan is invalid");
  }
  const { allowed_service: _allowed, forbidden_service: _forbidden, ...compiled } = plan;
  if (canonicalJson(compiled) !== canonicalJson(rebuilt)) throw new Error("approved WIF parity plan is invalid");
  return plan;
}

export function computePreexistingWifParityHash(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("WIF parity data is invalid");
  }
  const { parity_hash: _parityHash, ...body } = value;
  return parityDigest(body);
}

export function verifyPreexistingWifReadback({
  plan,
  serviceAccountUniqueId,
  region,
  providerBefore,
  providerAfter,
  serviceAccountPolicyBefore,
  serviceAccountPolicyAfter,
  allowedPolicyBefore,
  allowedPolicyAfter,
  forbiddenPolicyBefore,
  forbiddenPolicyAfter,
  observedBeforeAt,
  observedAfterAt,
}) {
  exact(serviceAccountUniqueId, UNIQUE_ID, "service account unique ID");
  if (!isRfc3339(observedBeforeAt) || !isRfc3339(observedAfterAt)
      || timestampNanoseconds(observedBeforeAt) >= timestampNanoseconds(observedAfterAt)) {
    throw new Error("WIF parity observation timeline is invalid");
  }
  exact(plan?.provider, PROVIDER, "plan provider");
  exact(plan?.provider_config_hash, /^[a-f0-9]{64}$/, "plan provider config hash");
  exact(plan?.impersonation_binding_hash, /^[a-f0-9]{64}$/, "plan impersonation binding hash");
  const beforeProvider = strictProvider(providerBefore, "WIF provider before");
  const afterProvider = strictProvider(providerAfter, "WIF provider after");
  const expectedProvider = beforeProvider.config;
  const finalProvider = afterProvider.config;
  const expectedConfigHash = digest(canonicalJson(expectedProvider));
  const finalConfigHash = digest(canonicalJson(finalProvider));
  if (providerBefore?.name !== plan?.provider || providerAfter?.name !== plan?.provider
      || providerBefore?.state !== "ACTIVE" || providerAfter?.state !== "ACTIVE"
      || expectedConfigHash !== plan?.provider_config_hash || finalConfigHash !== plan?.provider_config_hash
      || canonicalJson(beforeProvider.snapshot) !== canonicalJson(afterProvider.snapshot)) {
    throw new Error("preexisting WIF provider does not exactly match the approved plan");
  }
  exact(plan?.project_id, PROJECT_ID, "plan project ID");
  exact(plan?.project_number, /^\d+$/, "plan project number");
  exact(plan?.service_account, SERVICE_ACCOUNT, "plan service account");
  exact(region, REGION, "region");
  exact(plan?.allowed_service, SERVICE, "plan allowed service");
  exact(plan?.forbidden_service, SERVICE, "plan forbidden service");
  if (plan.allowed_service === plan.forbidden_service) throw new Error("allowed and forbidden services must be distinct");
  const ownerId = plan.attribute_condition?.match(/(?:^| && )assertion\.repository_owner_id=='(\d+)'(?: && |$)/)?.[1];
  const repositoryId = plan.impersonation_binding?.member?.match(/\/attribute\.repo_id\/(\d+)$/)?.[1];
  exact(ownerId, /^\d+$/, "plan owner ID");
  exact(repositoryId, /^\d+$/, "plan repository ID");
  const expectedMember = `principalSet://iam.googleapis.com/${plan.provider.replace(/\/providers\/[a-z0-9-]+$/, "")}/attribute.repo_id/${repositoryId}`;
  const expectedBinding = {
    resource: plan.service_account,
    role: "roles/iam.workloadIdentityUser",
    member: expectedMember,
  };
  const expectedEntry = canonicalJson({
    role: expectedBinding.role,
    member: expectedBinding.member,
    condition: null,
  }).trim();
  if (!exactObject(plan.impersonation_binding, new Set(["resource", "role", "member"]))
      || canonicalJson(plan.impersonation_binding) !== canonicalJson(expectedBinding)
      || plan.impersonation_binding_hash !== digest(canonicalJson(expectedBinding))) {
    throw new Error("preexisting WIF binding does not match the approved plan");
  }

  const serviceBefore = strictPolicy(serviceAccountPolicyBefore, "service-account policy before");
  const serviceAfter = strictPolicy(serviceAccountPolicyAfter, "service-account policy after");
  const allowedBefore = strictPolicy(allowedPolicyBefore, "allowed-service policy before");
  const allowedAfter = strictPolicy(allowedPolicyAfter, "allowed-service policy after");
  const forbiddenBefore = strictPolicy(forbiddenPolicyBefore, "forbidden-service policy before");
  const forbiddenAfter = strictPolicy(forbiddenPolicyAfter, "forbidden-service policy after");
  for (const [name, before, after] of [
    ["service-account", serviceBefore, serviceAfter],
    ["allowed-service", allowedBefore, allowedAfter],
    ["forbidden-service", forbiddenBefore, forbiddenAfter],
  ]) {
    if (before.hash !== after.hash || before.etag !== after.etag) {
      throw new Error(`${name} IAM policy drifted during the transaction`);
    }
  }

  const serviceEntries = serviceBefore.normalized.bindings;
  if (serviceEntries.filter((binding) => canonicalJson(binding).trim() === expectedEntry).length !== 1
      || serviceEntries.some((binding) => isWifMember(binding.member)
        && canonicalJson(binding).trim() !== expectedEntry)) {
    throw new Error("service-account WIF policy is not the exact preexisting binding");
  }
  const deployMember = `serviceAccount:${plan.service_account}`;
  const allowedEntry = canonicalJson({ role: "roles/run.developer", member: deployMember, condition: null }).trim();
  const allowedEntries = allowedBefore.normalized.bindings;
  if (allowedEntries.filter((binding) => canonicalJson(binding).trim() === allowedEntry).length !== 1
      || allowedEntries.some((binding) => isWifMember(binding.member)
        || (binding.member === deployMember && canonicalJson(binding).trim() !== allowedEntry))) {
    throw new Error("allowed-service IAM policy is not the exact deploy binding");
  }
  if (forbiddenBefore.normalized.bindings.some((binding) => binding.member === deployMember
      || isWifMember(binding.member))) {
    throw new Error("forbidden-service IAM policy grants deploy or WIF access");
  }

  const providerHash = digest(canonicalJson(beforeProvider.snapshot));
  const body = {
    mode: "PREEXISTING_EXACT",
    provider: plan.provider,
    provider_state: "ACTIVE",
    provider_config_hash: plan.provider_config_hash,
    provider_before_hash: providerHash,
    provider_after_hash: providerHash,
    service_account_policy_before_hash: serviceBefore.hash,
    service_account_policy_after_hash: serviceAfter.hash,
    service_account_etag_sha256: etagDigest(serviceBefore.etag),
    allowed_policy_before_hash: allowedBefore.hash,
    allowed_policy_after_hash: allowedAfter.hash,
    allowed_etag_sha256: etagDigest(allowedBefore.etag),
    forbidden_policy_before_hash: forbiddenBefore.hash,
    forbidden_policy_after_hash: forbiddenAfter.hash,
    forbidden_etag_sha256: etagDigest(forbiddenBefore.etag),
    expected_binding_hash: plan.impersonation_binding_hash,
    no_added_downstream_permissions: true,
    no_forbidden_access: true,
    owner_id: ownerId,
    repository_id: repositoryId,
    project_id: plan.project_id,
    project_number: plan.project_number,
    service_account_email: plan.service_account,
    service_account_unique_id: serviceAccountUniqueId,
    region,
    allowed_service: plan.allowed_service,
    forbidden_service: plan.forbidden_service,
    observed_before_at: observedBeforeAt,
    observed_after_at: observedAfterAt,
  };
  return { ...body, parity_hash: parityDigest(body) };
}

export function verifyWifReadback({
  plan,
  serviceAccountUniqueId,
  provider,
  serviceAccountPolicyBefore,
  serviceAccountPolicyAfter,
  allowedPolicyBefore,
  allowedPolicyAfter,
  forbiddenPolicyBefore,
  forbiddenPolicyAfter,
}) {
  exact(serviceAccountUniqueId, UNIQUE_ID, "service account unique ID");
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
  const scope = {
    project_id: plan.project_id,
    project_number: plan.project_number,
    service_account_email: plan.service_account,
    service_account_unique_id: serviceAccountUniqueId,
  };
  return {
    provider: { name: provider.name, config_hash: plan.provider_config_hash, state: provider.state, ...scope },
    policy: {
      policy_hash: digest(canonicalJson(normalizeIamPolicy(serviceAccountPolicyAfter))),
      iam_diff_hash: digest(canonicalJson(delta)),
      etag: serviceAccountPolicyAfter.etag,
      no_added_downstream_permissions: true,
      ...scope,
    },
  };
}

// Loaded lazily so the dependency-free console can import the pure verifiers
// in this module without shipping google-auth-library.
async function defaultGoogleAuth() {
  const { GoogleAuth } = await import("google-auth-library");
  return new GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform.read-only"] });
}

export function createGcpEvidenceReader({ auth, fetchImpl = fetch } = {}) {
  const authenticatedFetch = async (method, url, body) => {
    auth ??= await defaultGoogleAuth();
    const client = await auth.getClient();
    const authHeaders = await client.getRequestHeaders(url);
    const headers = new Headers(authHeaders);
    headers.set("content-type", "application/json");
    return fetchImpl(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(8_000),
    });
  };
  const requestWithResponse = async (method, url, body, expectedStatus) => {
    const response = await authenticatedFetch(method, url, body);
    const bytes = typeof response.arrayBuffer === "function"
      ? Buffer.from(await response.arrayBuffer())
      : Buffer.from(await response.text(), "utf8");
    if (bytes.length > 1_000_000) throw new Error("Google API response is too large");
    if (!response.ok || (expectedStatus !== undefined && response.status !== expectedStatus)) {
      throw new Error(`Google API ${method} failed with HTTP ${response.status}`);
    }
    let value;
    try {
      value = JSON.parse(decodeUtf8(bytes));
    } catch {
      throw new Error("Google API response is not valid JSON");
    }
    return { response, value };
  };
  const boundedParityRequest = async (method, url, body) => {
    let response;
    try {
      response = await authenticatedFetch(method, url, body);
    } catch {
      throw new Error("Google authenticated transport failed");
    }
    let length;
    let reader;
    let transport;
    try {
      const headers = response?.headers;
      const date = headers?.get?.("date");
      length = headers?.get?.("content-length");
      const status = response?.status;
      const ok = response?.ok;
      const responseBody = response?.body;
      reader = responseBody && typeof responseBody.getReader === "function" ? responseBody.getReader() : null;
      transport = { status, ok, headers: { get: (name) => name === "date" ? date : null } };
    } catch {
      throw new Error("Google authenticated response primitives are invalid");
    }
    const observedAt = parseAuthenticatedTransportObservation(transport, { expectedStatus: 200 });
    if (!reader) throw new Error(`Google API ${method} failed`);
    if (length !== null && (typeof length !== "string" || length.length > 16
        || !/^\d+$/.test(length) || Number(length) > MAX_PARITY_RESPONSE)) {
      try { await reader?.cancel(); } catch { /* static failure below */ }
      throw new Error("Google API response is too large");
    }
    const chunks = [];
    let total = 0;
    for (;;) {
      let done;
      let chunk;
      try {
        const part = await reader.read();
        if (!part || (typeof part !== "object" && typeof part !== "function")) throw new Error("invalid body part");
        done = part.done;
        const value = part.value;
        if (typeof done !== "boolean" || (done && value !== undefined)) throw new Error("invalid body part");
        if (!done) {
          if (!(value instanceof Uint8Array)) throw new Error("invalid body part");
          const byteLength = value.byteLength;
          if (!Number.isSafeInteger(byteLength) || byteLength < 0) throw new Error("invalid body part");
          chunk = Buffer.from(value);
          if (chunk.length !== byteLength) throw new Error("invalid body part");
        }
      } catch {
        try { await reader.cancel(); } catch { /* static failure below */ }
        throw new Error("Google API response body is invalid");
      }
      if (done) break;
      total += chunk.length;
      if (total > MAX_PARITY_RESPONSE) {
        try { await reader.cancel(); } catch { /* static failure below */ }
        throw new Error("Google API response is too large");
      }
      chunks.push(chunk);
    }
    let text;
    try {
      text = decodeUtf8(Buffer.concat(chunks, total));
    } catch {
      throw new Error("Google API response is not valid JSON");
    }
    let value;
    try {
      rejectDuplicateJsonKeys(text);
      value = JSON.parse(text);
    } catch (error) {
      if (error?.message === "duplicate JSON key") throw new Error("Google API response contains duplicate JSON keys");
      throw new Error("Google API response is not valid JSON");
    }
    return { value, observedAt };
  };
  const request = async (method, url, body) => (await requestWithResponse(method, url, body)).value;
  const prepareWifAuditLookup = ({
    projectId, provider, serviceAccountEmail, serviceAccountUniqueId, startTime, endTime,
  }) => {
    exact(projectId, PROJECT_ID, "project ID");
    exact(provider, PROVIDER, "provider");
    exact(serviceAccountEmail, SERVICE_ACCOUNT, "service account");
    exact(serviceAccountUniqueId, UNIQUE_ID, "service account unique ID");
    if (!isRfc3339(startTime) || !isRfc3339(endTime)) throw new Error("WIF audit time is invalid");
    const start = timestampNanoseconds(startTime);
    const end = timestampNanoseconds(endTime);
    if (end <= start || end - start > 10n * 60n * 1_000_000_000n) throw new Error("WIF audit time window is invalid");
    const stsMethod = "google.identity.sts.v1.SecurityTokenService.ExchangeToken";
    const iamMethods = ["GenerateAccessToken", "google.iam.credentials.v1.IAMCredentials.GenerateAccessToken"];
    const emailResource = `projects/-/serviceAccounts/${serviceAccountEmail}`;
    const numericResource = `projects/-/serviceAccounts/${serviceAccountUniqueId}`;
    return {
      projectId,
      provider,
      serviceAccountEmail,
      serviceAccountUniqueId,
      start,
      end,
      stsMethod,
      body: {
        resourceNames: [`projects/${projectId}`],
        filter: [
          `timestamp>=\"${startTime}\"`,
          `timestamp<=\"${endTime}\"`,
          `((protoPayload.methodName=\"${stsMethod}\" AND protoPayload.resourceName=\"${provider}\") OR ((protoPayload.methodName=\"${iamMethods[0]}\" OR protoPayload.methodName=\"${iamMethods[1]}\") AND (protoPayload.request.name=\"${emailResource}\" OR protoPayload.resourceName=\"${numericResource}\")))`,
        ].join(" AND "),
        orderBy: "timestamp asc",
        pageSize: 2,
      },
    };
  };
  const projectWifAuditEvidence = (value, lookup) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("WIF audit evidence is invalid");
    }
    if (Object.hasOwn(value, "nextPageToken")) throw new Error("WIF audit lookup is paginated");
    if (!Array.isArray(value.entries) || value.entries.length !== 2) throw new Error("WIF audit evidence is missing or ambiguous");
    const projectedEntries = value.entries.map((entry) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error("WIF audit evidence is invalid");
      const payload = entry.protoPayload;
      if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("WIF audit evidence is invalid");
      const protoPayload = Object.fromEntries(Object.entries(payload)
        .filter(([key]) => ["@type", "authenticationInfo", "metadata", "methodName", "request", "resourceName", "serviceName", "status"].includes(key)));
      if (payload.methodName === lookup.stsMethod) {
        const stsRequest = payload.request;
        if (!exactObject(stsRequest, STS_REQUEST_FIELDS)
            || stsRequest["@type"] !== "type.googleapis.com/google.identity.sts.v1.ExchangeTokenRequest"
            || stsRequest.grantType !== "urn:ietf:params:oauth:grant-type:token-exchange") {
          throw new Error("WIF STS audit request is invalid");
        }
        protoPayload.request = {
          "@type": stsRequest["@type"],
          grantType: stsRequest.grantType,
        };
      }
      return { insertId: entry.insertId, timestamp: entry.timestamp, protoPayload, resource: entry.resource };
    });
    const projection = Buffer.from(canonicalJson({ entries: projectedEntries }));
    const parsed = parseWifAuditEvidence(projection);
    if (parsed.provider !== lookup.provider || parsed.project_id !== lookup.projectId
        || parsed.service_account_email !== lookup.serviceAccountEmail
        || parsed.service_account_unique_id !== lookup.serviceAccountUniqueId
        || timestampNanoseconds(parsed.exchanged_at) < lookup.start
        || timestampNanoseconds(parsed.authenticated_at) > lookup.end) {
      throw new Error("WIF audit evidence does not match the requested scope");
    }
    return { projection, parsed };
  };
  return {
    async readPreexistingWifParity({ plan, scope }) {
      const approvedPlan = snapshotPlainJson(plan, "approved WIF parity plan");
      const approvedScope = snapshotPlainJson(scope, "approved WIF parity scope");
      if (!exactObject(approvedPlan, PARITY_PLAN_FIELDS) || !exactObject(approvedScope, PARITY_SCOPE_FIELDS)) {
        throw new Error("approved WIF parity plan scope is invalid");
      }
      validateApprovedParityPlan(approvedPlan);
      exact(approvedPlan?.project_id, PROJECT_ID, "plan project ID");
      exact(approvedPlan?.project_number, /^\d+$/, "plan project number");
      exact(approvedPlan?.provider, PROVIDER, "plan provider");
      exact(approvedPlan?.service_account, SERVICE_ACCOUNT, "plan service account");
      exact(approvedPlan?.allowed_service, SERVICE, "plan allowed service");
      exact(approvedPlan?.forbidden_service, SERVICE, "plan forbidden service");
      exact(approvedScope?.project_id, PROJECT_ID, "scope project ID");
      exact(approvedScope?.project_number, /^\d+$/, "scope project number");
      exact(approvedScope?.region, REGION, "scope region");
      exact(approvedScope?.service_account_email, SERVICE_ACCOUNT, "scope service account");
      exact(approvedScope?.service_account_unique_id, UNIQUE_ID, "scope service account unique ID");
      exact(approvedScope?.allowed_service, SERVICE, "scope allowed service");
      exact(approvedScope?.forbidden_service, SERVICE, "scope forbidden service");
      if (!approvedPlan.provider.startsWith(`projects/${approvedPlan.project_number}/`)
          || approvedPlan.allowed_service === approvedPlan.forbidden_service
          || approvedPlan.project_id !== approvedScope.project_id
          || approvedPlan.project_number !== approvedScope.project_number
          || approvedPlan.service_account !== approvedScope.service_account_email
          || approvedPlan.allowed_service !== approvedScope.allowed_service
          || approvedPlan.forbidden_service !== approvedScope.forbidden_service) {
        throw new Error("approved WIF parity plan scope is invalid");
      }

      const accountNames = new Set([
        `projects/${approvedPlan.project_id}/serviceAccounts/${approvedPlan.service_account}`,
        `projects/${approvedPlan.project_id}/serviceAccounts/${approvedScope.service_account_unique_id}`,
        `projects/-/serviceAccounts/${approvedPlan.service_account}`,
        `projects/-/serviceAccounts/${approvedScope.service_account_unique_id}`,
      ]);
      const providerUrl = `https://iam.googleapis.com/v1/${approvedPlan.provider}`;
      const accountUrl = `https://iam.googleapis.com/v1/projects/${approvedPlan.project_id}/serviceAccounts/${encodeURIComponent(approvedPlan.service_account)}`;
      const accountPolicyUrl = `${accountUrl}:getIamPolicy`;
      const cloudPolicyUrl = (service) => `https://run.googleapis.com/v2/projects/${approvedPlan.project_id}/locations/${approvedScope.region}/services/${service}:getIamPolicy?options.requestedPolicyVersion=3`;
      const policyBody = { options: { requestedPolicyVersion: 3 } };
      let previousTime;
      const observedRequest = async (method, url, body) => {
        const { value, observedAt } = await boundedParityRequest(method, url, body);
        const observed = timestampNanoseconds(observedAt);
        if (previousTime !== undefined && observed < previousTime) {
          throw new Error("WIF parity transport observations regress");
        }
        previousTime = observed;
        return { value, observedAt };
      };

      const providerBefore = (await observedRequest("GET", providerUrl)).value;
      const account = (await observedRequest("GET", accountUrl)).value;
      if (!account || typeof account !== "object" || Array.isArray(account)
          || Object.hasOwn(account, "nextPageToken") || !accountNames.has(account.name)
          || account.projectId !== approvedPlan.project_id || account.email !== approvedPlan.service_account
          || account.uniqueId !== approvedScope.service_account_unique_id) {
        throw new Error("service account identity does not match the approved plan");
      }
      const serviceAccountPolicyBefore = (await observedRequest("POST", accountPolicyUrl, policyBody)).value;
      const allowedPolicyBefore = (await observedRequest("GET", cloudPolicyUrl(approvedPlan.allowed_service))).value;
      const forbiddenBefore = await observedRequest("GET", cloudPolicyUrl(approvedPlan.forbidden_service));
      const providerAfter = (await observedRequest("GET", providerUrl)).value;
      const serviceAccountPolicyAfter = (await observedRequest("POST", accountPolicyUrl, policyBody)).value;
      const allowedPolicyAfter = (await observedRequest("GET", cloudPolicyUrl(approvedPlan.allowed_service))).value;
      const forbiddenAfter = await observedRequest("GET", cloudPolicyUrl(approvedPlan.forbidden_service));
      if (timestampNanoseconds(forbiddenBefore.observedAt) >= timestampNanoseconds(forbiddenAfter.observedAt)) {
        throw new Error("WIF parity transport observation boundary is not strict");
      }
      const parity = verifyPreexistingWifReadback({
        plan: approvedPlan,
        serviceAccountUniqueId: approvedScope.service_account_unique_id,
        region: approvedScope.region,
        providerBefore,
        providerAfter,
        serviceAccountPolicyBefore,
        serviceAccountPolicyAfter,
        allowedPolicyBefore,
        allowedPolicyAfter,
        forbiddenPolicyBefore: forbiddenBefore.value,
        forbiddenPolicyAfter: forbiddenAfter.value,
        observedBeforeAt: forbiddenBefore.observedAt,
        observedAfterAt: forbiddenAfter.observedAt,
      });
      if (parity.owner_id !== approvedScope.owner_id || parity.repository_id !== approvedScope.repository_id
          || parity.project_id !== approvedScope.project_id || parity.project_number !== approvedScope.project_number
          || parity.region !== approvedScope.region || parity.service_account_email !== approvedScope.service_account_email
          || parity.service_account_unique_id !== approvedScope.service_account_unique_id
          || parity.allowed_service !== approvedScope.allowed_service
          || parity.forbidden_service !== approvedScope.forbidden_service) {
        throw new Error("WIF parity output does not match the approved scope");
      }
      return parity;
    },
    async readCloudRunRevision({ projectId, region, service }) {
      exact(projectId, PROJECT_ID, "project ID");
      exact(region, REGION, "region");
      exact(service, SERVICE, "service");
      const serviceName = `projects/${projectId}/locations/${region}/services/${service}`;
      const value = await request("GET", `https://run.googleapis.com/v2/${serviceName}`);
      const revision = value.latestReadyRevision?.split("/").at(-1);
      if (!exact(revision, SERVICE, "latest ready revision")) throw new Error("Cloud Run service has no valid latest ready revision");
      const revisionName = `${serviceName}/revisions/${revision}`;
      const deployed = await request("GET", `https://run.googleapis.com/v2/${revisionName}`);
      if (deployed.name !== revisionName || !isRfc3339(deployed.createTime)) {
        throw new Error("Cloud Run revision identity is invalid");
      }
      const containers = deployed.containers;
      if (!Array.isArray(containers) || containers.length !== 1) {
        throw new Error("Cloud Run revision container is missing or ambiguous");
      }
      const releases = (containers[0].env ?? [])
        .filter(({ name }) => name === "RELEASE").map(({ value: release }) => release);
      if (releases.length !== 1 || !/^[a-z0-9][a-z0-9-]{0,19}$/.test(releases[0])) {
        throw new Error("Cloud Run revision release marker is missing or ambiguous");
      }
      const image = containers[0].image;
      const imageDigest = typeof image === "string" ? image.match(/@((?:sha256:)[a-f0-9]{64})$/)?.[1] : undefined;
      if (!imageDigest) throw new Error("Cloud Run revision image digest is missing");
      return {
        project_id: projectId,
        region,
        service,
        revision,
        create_time: deployed.createTime,
        release_marker: releases[0],
        image_digest: imageDigest,
      };
    },
    async readNamedCloudRunRevision({
      projectId, region, service, revision, expectedReleaseMarker,
    }) {
      exact(projectId, PROJECT_ID, "project ID");
      exact(region, REGION, "region");
      exact(service, SERVICE, "service");
      exact(revision, SERVICE, "revision");
      exact(expectedReleaseMarker, /^[a-z0-9][a-z0-9-]{0,19}$/, "expected release marker");
      const expectedRevision = `${service}-${expectedReleaseMarker}`;
      if (!SERVICE.test(expectedRevision) || revision !== expectedRevision) {
        throw new Error("named Cloud Run revision does not match its service and release marker");
      }
      const revisionName = `projects/${projectId}/locations/${region}/services/${service}/revisions/${revision}`;
      const { response, value } = await requestWithResponse(
        "GET",
        `https://run.googleapis.com/v2/${revisionName}`,
        undefined,
        200,
      );
      if (!value || typeof value !== "object" || Array.isArray(value)
          || Object.hasOwn(value, "nextPageToken") || value.name !== revisionName
          || !isRfc3339(value.createTime)) {
        throw new Error("named Cloud Run revision identity is invalid");
      }
      if (!Array.isArray(value.conditions)) throw new Error("named Cloud Run revision readiness is invalid");
      const ready = value.conditions.filter((condition) => condition?.type === "Ready");
      if (ready.length !== 1 || ready[0].state !== "CONDITION_SUCCEEDED") {
        throw new Error("named Cloud Run revision is not terminal-ready");
      }
      if (!Array.isArray(value.containers) || value.containers.length !== 1) {
        throw new Error("named Cloud Run revision container is missing or ambiguous");
      }
      const releases = (value.containers[0].env ?? [])
        .filter(({ name }) => name === "RELEASE").map(({ value: marker }) => marker);
      if (releases.length !== 1 || releases[0] !== expectedReleaseMarker) {
        throw new Error("named Cloud Run revision release marker does not match");
      }
      const image = value.containers[0].image;
      const imageDigest = immutableImageDigest(image);
      if (!imageDigest) throw new Error("named Cloud Run revision image digest is missing");
      const observedAt = parseAuthenticatedTransportObservation(response, {
        expectedStatus: 200,
        sourceEventTimes: [value.createTime],
      });
      return {
        project_id: projectId,
        region,
        service,
        revision,
        create_time: value.createTime,
        release_marker: releases[0],
        image_digest: imageDigest,
        observed_at: observedAt,
      };
    },
    async readExactCloudRunRevisionObservation(input) {
      const approved = snapshotPlainJson(input, "exact Cloud Run revision request");
      if (!exactObject(approved, EXACT_REVISION_FIELDS)) {
        throw new Error("exact Cloud Run revision request is invalid");
      }
      exact(approved.projectId, PROJECT_ID, "project ID");
      exact(approved.region, REGION, "region");
      exact(approved.service, CANONICAL_RESOURCE_ID, "service");
      exact(approved.revision, IMMUTABLE_REVISION, "revision");
      exact(approved.expectedReleaseMarker, /^[a-z0-9][a-z0-9-]{0,19}$/, "expected release marker");
      if (!isRfc3339(approved.expectedCreateTime)) throw new Error("expected revision create time is invalid");
      exact(approved.expectedImageDigest, /^sha256:[a-f0-9]{64}$/, "expected image digest");

      const revisionName = `projects/${approved.projectId}/locations/${approved.region}/services/${approved.service}/revisions/${approved.revision}`;
      const { value, observedAt } = await boundedParityRequest(
        "GET",
        `https://run.googleapis.com/v2/${revisionName}`,
      );
      if (!value || typeof value !== "object" || Array.isArray(value)
          || Object.hasOwn(value, "nextPageToken") || value.name !== revisionName
          || !isRfc3339(value.createTime) || value.createTime !== approved.expectedCreateTime) {
        throw new Error("exact Cloud Run revision identity is invalid");
      }
      if (!Array.isArray(value.conditions)) throw new Error("exact Cloud Run revision readiness is invalid");
      const ready = value.conditions.filter((condition) => condition?.type === "Ready");
      if (ready.length !== 1 || ready[0].state !== "CONDITION_SUCCEEDED") {
        throw new Error("exact Cloud Run revision is not terminal-ready");
      }
      if (!Array.isArray(value.containers) || value.containers.length !== 1) {
        throw new Error("exact Cloud Run revision container is missing or ambiguous");
      }
      const releases = (value.containers[0].env ?? [])
        .filter(({ name }) => name === "RELEASE").map(({ value: marker }) => marker);
      if (releases.length !== 1 || releases[0] !== approved.expectedReleaseMarker) {
        throw new Error("exact Cloud Run revision release marker does not match");
      }
      const imageDigest = immutableImageDigest(value.containers[0].image);
      if (imageDigest !== approved.expectedImageDigest) {
        throw new Error("exact Cloud Run revision image digest does not match");
      }
      if (timestampNanoseconds(value.createTime) > timestampNanoseconds(observedAt)) {
        throw new Error("exact Cloud Run revision occurrence is after observation");
      }
      return {
        project_id: approved.projectId,
        region: approved.region,
        service: approved.service,
        revision: approved.revision,
        create_time: value.createTime,
        release_marker: releases[0],
        image_digest: imageDigest,
        observed_at: observedAt,
      };
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
    async readWifAuditEvidence({
      projectId, provider, serviceAccountEmail, serviceAccountUniqueId, startTime, endTime,
    }) {
      const lookup = prepareWifAuditLookup({
        projectId, provider, serviceAccountEmail, serviceAccountUniqueId, startTime, endTime,
      });
      const value = await request("POST", "https://logging.googleapis.com/v2/entries:list", lookup.body);
      return projectWifAuditEvidence(value, lookup).projection;
    },
    async readWifAuditEvidenceObserved({
      projectId, provider, serviceAccountEmail, serviceAccountUniqueId, startTime, endTime,
    }) {
      const lookup = prepareWifAuditLookup({
        projectId, provider, serviceAccountEmail, serviceAccountUniqueId, startTime, endTime,
      });
      const { value, observedAt } = await boundedParityRequest(
        "POST", "https://logging.googleapis.com/v2/entries:list", lookup.body,
      );
      const { projection, parsed } = projectWifAuditEvidence(value, lookup);
      const observed = timestampNanoseconds(observedAt);
      if (timestampNanoseconds(parsed.exchanged_at) > observed
          || timestampNanoseconds(parsed.authenticated_at) > observed) {
        throw new Error("WIF audit occurrence is after its authenticated observation");
      }
      return { projection: Buffer.from(projection), observedAt };
    },
    async readServiceAccountPolicy({ serviceAccount }) {
      exact(serviceAccount, SERVICE_ACCOUNT, "service account");
      return request(
        "POST",
        `https://iam.googleapis.com/v1/projects/-/serviceAccounts/${encodeURIComponent(serviceAccount)}:getIamPolicy`,
        { options: { requestedPolicyVersion: 3 } },
      );
    },
    async readDisableAuditEntry({ projectId, projectNumber, keyResource, humanActor, startTime, endTime }) {
      exact(projectId, PROJECT_ID, "project ID");
      exact(projectNumber, /^\d+$/, "project number");
      exact(keyResource, KEY_RESOURCE, "key resource");
      exact(humanActor, ACTOR, "human actor");
      if (!isRfc3339(startTime) || !isRfc3339(endTime)) throw new Error("audit time is invalid");
      const start = timestampNanoseconds(startTime);
      const end = timestampNanoseconds(endTime);
      if (end <= start || end - start > 24n * 60n * 60n * 1_000_000_000n) {
        throw new Error("audit time window is invalid");
      }
      const [, keyProject, accountIdentifier, keyId] = KEY_RESOURCE.exec(keyResource);
      if (!["-", projectId].includes(keyProject)) throw new Error("key resource project does not match");
      const account = await request(
        "GET",
        `https://iam.googleapis.com/v1/projects/-/serviceAccounts/${encodeURIComponent(accountIdentifier)}`,
      );
      if (!exact(account.email, SERVICE_ACCOUNT, "service account email")
          || !exact(account.uniqueId, UNIQUE_ID, "service account unique ID")
          || ![account.email, account.uniqueId].includes(accountIdentifier)) {
        throw new Error("service account identity does not match");
      }
      // Verified against the live 2026-08-14 DisableServiceAccountKey entry: Cloud Audit
      // Logs records the `-` wildcard with the numeric unique ID, not the concrete project.
      const auditResource = `projects/-/serviceAccounts/${account.uniqueId}/keys/${keyId}`;
      const method = "google.iam.admin.v1.DisableServiceAccountKey";
      const value = await request("POST", "https://logging.googleapis.com/v2/entries:list", {
        resourceNames: [`projects/${projectId}`],
        filter: [
          `protoPayload.methodName=\"${method}\"`,
          `protoPayload.resourceName=\"${auditResource}\"`,
          `protoPayload.authenticationInfo.principalEmail=\"${humanActor}\"`,
          `timestamp>=\"${startTime}\"`,
          `timestamp<=\"${endTime}\"`,
        ].join(" AND "),
        orderBy: "timestamp desc",
        pageSize: 10,
      });
      if (Object.hasOwn(value, "nextPageToken")) throw new Error("key-disable audit lookup is paginated");
      const matches = (value.entries ?? []).filter((entry) => entry?.protoPayload?.methodName === method
        && entry.protoPayload.resourceName === auditResource
        && entry.protoPayload.authenticationInfo?.principalEmail === humanActor
        && (entry.protoPayload.status?.code === undefined || entry.protoPayload.status.code === 0)
        && isRfc3339(entry.timestamp)
        && timestampNanoseconds(entry.timestamp) >= start && timestampNanoseconds(entry.timestamp) <= end);
      if (matches.length !== 1 || typeof matches[0].insertId !== "string") {
        throw new Error("exact human key-disable audit entry is missing or ambiguous");
      }
      return {
        method_name: method,
        resource_name: auditResource,
        key_id: keyId,
        service_account_email: account.email,
        service_account_unique_id: account.uniqueId,
        project_id: projectId,
        project_number: projectNumber,
        principal_email: humanActor,
        insert_id: matches[0].insertId,
        timestamp: matches[0].timestamp,
        status: "SUCCEEDED",
      };
    },
    async readDisableAuditEntryObserved({
      projectId,
      projectNumber,
      serviceAccountEmail,
      serviceAccountUniqueId,
      keyResource,
      humanActor,
      startTime,
      endTime,
    }) {
      exact(projectId, PROJECT_ID, "project ID");
      exact(projectNumber, /^\d+$/, "project number");
      exact(serviceAccountEmail, SERVICE_ACCOUNT, "service account email");
      exact(serviceAccountUniqueId, UNIQUE_ID, "service account unique ID");
      exact(keyResource, KEY_RESOURCE, "key resource");
      exact(humanActor, HUMAN_ACTOR, "human actor");
      if (!isRfc3339(startTime) || !isRfc3339(endTime)) throw new Error("audit time is invalid");
      const start = timestampNanoseconds(startTime);
      const end = timestampNanoseconds(endTime);
      if (end <= start || end - start > 24n * 60n * 60n * 1_000_000_000n) {
        throw new Error("audit time window is invalid");
      }
      const [, keyProject, accountIdentifier, keyId] = KEY_RESOURCE.exec(keyResource);
      if (!["-", projectId].includes(keyProject)
          || ![serviceAccountEmail, serviceAccountUniqueId].includes(accountIdentifier)) {
        throw new Error("key resource project or service account does not match");
      }
      const identity = await boundedParityRequest(
        "GET",
        `https://iam.googleapis.com/v1/projects/-/serviceAccounts/${encodeURIComponent(accountIdentifier)}`,
      );
      const account = identity.value;
      const accountNames = new Set([
        `projects/${projectId}/serviceAccounts/${serviceAccountEmail}`,
        `projects/${projectId}/serviceAccounts/${serviceAccountUniqueId}`,
        `projects/-/serviceAccounts/${serviceAccountEmail}`,
        `projects/-/serviceAccounts/${serviceAccountUniqueId}`,
      ]);
      if (!account || typeof account !== "object" || Array.isArray(account)
          || Object.hasOwn(account, "nextPageToken")
          || account.projectId !== projectId
          || (Object.hasOwn(account, "disabled") && account.disabled !== false)
          || !accountNames.has(account.name)
          || account.email !== serviceAccountEmail || account.uniqueId !== serviceAccountUniqueId) {
        throw new Error("service account identity does not match");
      }
      // Same verified shape as above: `-` wildcard plus numeric unique ID.
      const auditResource = `projects/-/serviceAccounts/${serviceAccountUniqueId}/keys/${keyId}`;
      const method = "google.iam.admin.v1.DisableServiceAccountKey";
      const audit = await boundedParityRequest("POST", "https://logging.googleapis.com/v2/entries:list", {
        resourceNames: [`projects/${projectId}`],
        filter: [
          `protoPayload.methodName=\"${method}\"`,
          `protoPayload.resourceName=\"${auditResource}\"`,
          `protoPayload.authenticationInfo.principalEmail=\"${humanActor}\"`,
          `timestamp>=\"${startTime}\"`,
          `timestamp<=\"${endTime}\"`,
        ].join(" AND "),
        orderBy: "timestamp desc",
        pageSize: 10,
      });
      if (timestampNanoseconds(identity.observedAt) > timestampNanoseconds(audit.observedAt)) {
        throw new Error("key-disable authenticated observations regress");
      }
      const value = audit.value;
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("key-disable audit evidence is invalid");
      }
      if (Object.hasOwn(value, "nextPageToken")) throw new Error("key-disable audit lookup is paginated");
      if (!Array.isArray(value.entries)) throw new Error("exact human key-disable audit entry is missing or ambiguous");
      const matches = value.entries.filter((entry) => entry?.protoPayload?.methodName === method
        && entry.protoPayload.resourceName === auditResource
        && entry.protoPayload.authenticationInfo?.principalEmail === humanActor
        && (entry.protoPayload.status === undefined
          || exactObject(entry.protoPayload.status, new Set())
          || (exactObject(entry.protoPayload.status, new Set(["code"])) && entry.protoPayload.status.code === 0))
        && isRfc3339(entry.timestamp)
        && timestampNanoseconds(entry.timestamp) >= start && timestampNanoseconds(entry.timestamp) <= end
        && timestampNanoseconds(entry.timestamp) <= timestampNanoseconds(audit.observedAt));
      if (value.entries.length !== 1 || matches.length !== 1
          || typeof matches[0].insertId !== "string" || !matches[0].insertId) {
        throw new Error("exact human key-disable audit entry is missing or ambiguous");
      }
      return {
        evidence: {
          method_name: method,
          resource_name: auditResource,
          key_id: keyId,
          service_account_email: serviceAccountEmail,
          service_account_unique_id: serviceAccountUniqueId,
          project_id: projectId,
          project_number: projectNumber,
          principal_email: humanActor,
          insert_id: matches[0].insertId,
          timestamp: matches[0].timestamp,
          status: "SUCCEEDED",
        },
        observedAt: audit.observedAt,
      };
    },
  };
}
