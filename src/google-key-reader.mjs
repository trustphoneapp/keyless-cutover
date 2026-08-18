import { GoogleAuth } from "google-auth-library";

import { decodeUtf8 } from "./evidence-artifact.mjs";
import { parseAuthenticatedTransportObservation, rejectDuplicateJsonKeys } from "./observation-time.mjs";

const SERVICE_ACCOUNT_EMAIL = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;
const KEY_ID = /^[a-f0-9]{40}$/;
const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const MAX_KEY_RESPONSE = 64_000;

function exact(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

async function readObservedKeyResponse(response) {
  let observedAt;
  let length;
  let reader;
  let transport;
  try {
    const responseHeaders = response?.headers;
    const date = responseHeaders?.get?.("date");
    const status = response?.status;
    const ok = response?.ok;
    length = responseHeaders?.get?.("content-length");
    const body = response?.body;
    reader = body && typeof body.getReader === "function" ? body.getReader() : null;
    transport = {
      status,
      ok,
      headers: { get: (name) => name === "date" ? date : null },
    };
    observedAt = parseAuthenticatedTransportObservation(transport, { expectedStatus: 200 });
  } catch {
    throw new Error("Google key response primitives are invalid");
  }
  if (!reader || (length !== null && (typeof length !== "string" || length.length > 16
    || !/^\d+$/.test(length) || Number(length) > MAX_KEY_RESPONSE))) {
    try { await reader?.cancel(); } catch { /* static failure below */ }
    throw new Error("Google key response is invalid or too large");
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
      throw new Error("Google key response body is invalid");
    }
    if (done) break;
    total += chunk.length;
    if (total > MAX_KEY_RESPONSE) {
      try { await reader.cancel(); } catch { /* static failure below */ }
      throw new Error("Google key response is too large");
    }
    chunks.push(chunk);
  }
  let text;
  try { text = decodeUtf8(Buffer.concat(chunks, total)); } catch { throw new Error("Google key response is not valid UTF-8"); }
  let value;
  try {
    rejectDuplicateJsonKeys(text);
    value = JSON.parse(text);
  } catch (error) {
    if (error?.message === "duplicate JSON key") throw new Error("Google key response contains duplicate JSON keys");
    throw new Error("Google key response is not valid JSON");
  }
  try {
    observedAt = parseAuthenticatedTransportObservation(transport, {
      expectedStatus: 200,
      sourceEventTimes: [value?.validAfterTime],
    });
  } catch {
    throw new Error("Google key timeline is invalid");
  }
  return { value, observedAt };
}

export function createGoogleKeyReaderObserved({
  auth = new GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform.read-only"] }),
  fetchImpl = fetch,
} = {}) {
  return async ({
    client_email: clientEmail, private_key_id: privateKeyId, project_id: projectId, expected_disabled: expectedDisabled,
  }) => {
    exact(clientEmail, SERVICE_ACCOUNT_EMAIL, "client_email");
    exact(privateKeyId, KEY_ID, "private_key_id");
    exact(projectId, PROJECT_ID, "project_id");
    if (typeof expectedDisabled !== "boolean") throw new Error("expected_disabled is invalid");
    // keys.get echoes the concrete project ID, not the `-` wildcard used in the request path.
    const acceptedNames = new Set([
      `projects/-/serviceAccounts/${clientEmail}/keys/${privateKeyId}`,
      `projects/${projectId}/serviceAccounts/${clientEmail}/keys/${privateKeyId}`,
    ]);
    const url = `https://iam.googleapis.com/v1/projects/-/serviceAccounts/${encodeURIComponent(clientEmail)}/keys/${privateKeyId}`;
    let response;
    try {
      const client = await auth.getClient();
      const requestHeaders = await client.getRequestHeaders(url);
      response = await fetchImpl(url, {
        headers: requestHeaders,
        redirect: "error",
        signal: AbortSignal.timeout(5_000),
      });
    } catch {
      throw new Error("Google key authenticated transport failed");
    }
    const { value: key, observedAt } = await readObservedKeyResponse(response);
    const validAfterTime = key?.validAfterTime;
    const disabled = key?.disabled ?? false;
    if (!key || typeof key !== "object" || Array.isArray(key)
        || !acceptedNames.has(key.name) || key.keyType !== "USER_MANAGED" || key.keyAlgorithm !== "KEY_ALG_RSA_2048"
        || (key.disabled !== undefined && typeof key.disabled !== "boolean") || disabled !== expectedDisabled) {
      throw new Error("Google key identity, state, type, or algorithm is invalid");
    }
    return {
      key: {
        name: key.name,
        keyType: key.keyType,
        keyAlgorithm: key.keyAlgorithm,
        disabled,
        validAfterTime,
      },
      observedAt,
    };
  };
}

export function createGoogleKeyReader({
  auth = new GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform.read-only"] }),
  fetchImpl = fetch,
} = {}) {
  return async ({ client_email: clientEmail, private_key_id: privateKeyId }) => {
    exact(clientEmail, SERVICE_ACCOUNT_EMAIL, "client_email");
    exact(privateKeyId, KEY_ID, "private_key_id");
    const name = `projects/-/serviceAccounts/${encodeURIComponent(clientEmail)}/keys/${privateKeyId}`;
    const url = `https://iam.googleapis.com/v1/${name}`;
    const client = await auth.getClient();
    const headers = await client.getRequestHeaders(url);
    const response = await fetchImpl(url, {
      headers,
      redirect: "error",
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok) throw new Error(`Google key lookup failed with HTTP ${response.status}`);
    const body = await response.text();
    if (body.length > 64_000) throw new Error("Google key lookup response is too large");
    const key = JSON.parse(body);
    if (key.disabled !== undefined && typeof key.disabled !== "boolean") {
      throw new Error("Google key disabled state is invalid");
    }
    return { ...key, disabled: key.disabled ?? false };
  };
}
