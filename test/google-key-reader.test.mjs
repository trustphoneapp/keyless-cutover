import assert from "node:assert/strict";
import test from "node:test";

import { createGoogleKeyReader, createGoogleKeyReaderObserved } from "../src/google-key-reader.mjs";

const clientEmail = "deploy@example.iam.gserviceaccount.com";
const privateKeyId = "a".repeat(40);
const projectId = "example-project";
// Real keys.get responses echo the concrete project ID (see docs/evidence/K0_DISABLE_RECEIPT_2026-08-14.json).
const keyName = `projects/${projectId}/serviceAccounts/${clientEmail}/keys/${privateKeyId}`;

function keyResponse(value, { date = "Thu, 13 Aug 2026 12:01:00 GMT", status = 200, headers = {} } = {}) {
  const body = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
  return new Response(body, { status, headers: { date, ...headers } });
}

function validKey(overrides = {}) {
  return {
    name: keyName,
    keyType: "USER_MANAGED",
    keyAlgorithm: "KEY_ALG_RSA_2048",
    validAfterTime: "2026-08-13T12:00:00Z",
    disabled: false,
    ...overrides,
  };
}

function observedReader(fetchImpl, auth = {
  getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }),
}) {
  return createGoogleKeyReaderObserved({ auth, fetchImpl });
}

function observedArguments(overrides = {}) {
  return { client_email: clientEmail, private_key_id: privateKeyId, project_id: projectId, expected_disabled: false, ...overrides };
}

test("Google key reader performs one bounded authenticated exact-key lookup", async () => {
  const requests = [];
  const reader = createGoogleKeyReader({
    auth: {
      getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }),
    },
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          name: "projects/-/serviceAccounts/deploy@example.iam.gserviceaccount.com/keys/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          keyType: "USER_MANAGED",
          keyAlgorithm: "KEY_ALG_RSA_2048",
        }),
      };
    },
  });
  const key = await reader({
    client_email: "deploy@example.iam.gserviceaccount.com",
    private_key_id: "a".repeat(40),
  });
  assert.equal(key.disabled, false);
  assert.equal(requests.length, 1);
  assert.match(requests[0].url, /deploy%40example\.iam\.gserviceaccount\.com\/keys\/a{40}$/);
  assert.equal(requests[0].options.headers.authorization, "Bearer test");
});

test("Google key reader preserves an explicit disabled state", async () => {
  const reader = createGoogleKeyReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({
        name: "projects/example/serviceAccounts/deploy@example.iam.gserviceaccount.com/keys/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        keyType: "USER_MANAGED",
        keyAlgorithm: "KEY_ALG_RSA_2048",
        disabled: true,
      }),
    }),
  });
  const key = await reader({
    client_email: "deploy@example.iam.gserviceaccount.com",
    private_key_id: "a".repeat(40),
  });
  assert.equal(key.disabled, true);
});

test("Google key reader binds the returned key to the requested account and rejects junk", async () => {
  const respond = (value) => createGoogleKeyReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async () => ({ ok: true, status: 200, text: async () => JSON.stringify(value) }),
  })({ client_email: "deploy@example.iam.gserviceaccount.com", private_key_id: "a".repeat(40) });
  const valid = {
    name: "projects/-/serviceAccounts/deploy@example.iam.gserviceaccount.com/keys/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    keyType: "USER_MANAGED",
    keyAlgorithm: "KEY_ALG_RSA_2048",
  };
  // Previously a nameless, typeless body was returned verbatim to the caller.
  await assert.rejects(respond({ disabled: true }), /identity, type, or algorithm/);
  await assert.rejects(respond({ ...valid, name: valid.name.replace(/keys\/a+$/, `keys/${"b".repeat(40)}`) }), /identity/);
  await assert.rejects(respond({ ...valid, keyType: "SYSTEM_MANAGED" }), /identity/);
  await assert.rejects(respond({ ...valid, keyAlgorithm: "KEY_ALG_RSA_1024" }), /identity/);
  const key = await respond(valid);
  assert.deepEqual(Object.keys(key).sort(), ["disabled", "keyAlgorithm", "keyType", "name"]);
});

test("Google key reader rejects an oversized declared body before buffering", async () => {
  const reader = createGoogleKeyReader({
    auth: { getClient: async () => ({ getRequestHeaders: async () => ({ authorization: "Bearer test" }) }) },
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      headers: { get: (name) => name === "content-length" ? "999999" : null },
      text: async () => { throw new Error("body must not be buffered"); },
    }),
  });
  await assert.rejects(
    reader({ client_email: "deploy@example.iam.gserviceaccount.com", private_key_id: "a".repeat(40) }),
    /too large/,
  );
});

test("Google key reader rejects malformed identity before authentication", async () => {
  let called = false;
  const reader = createGoogleKeyReader({ auth: { getClient: async () => { called = true; } } });
  await assert.rejects(reader({ client_email: "bad", private_key_id: "a".repeat(40) }), /client_email/);
  assert.equal(called, false);
});

test("observed Google key reader returns one exact authenticated key projection and time", async () => {
  const requests = [];
  const result = await observedReader(async (url, options) => {
    requests.push({ url, options });
    return keyResponse(validKey());
  })(observedArguments());
  assert.deepEqual(result, {
    key: validKey(),
    observedAt: "2026-08-13T12:01:00.000Z",
  });
  assert.equal(requests.length, 1);
  assert.match(requests[0].url, /deploy%40example\.iam\.gserviceaccount\.com\/keys\/a{40}$/);
  assert.equal(requests[0].options.headers.authorization, "Bearer test");
});

test("observed Google key reader rejects identity, state, type, algorithm, and event drift", async () => {
  const attacks = [
    validKey({ name: `${keyName}0` }),
    validKey({ name: `projects/other-project/serviceAccounts/${clientEmail}/keys/${privateKeyId}` }),
    validKey({ disabled: true }),
    validKey({ disabled: "false" }),
    validKey({ keyType: "SYSTEM_MANAGED" }),
    validKey({ keyAlgorithm: ["KEY", "ALG", "RSA", "3072"].join("_") }),
    validKey({ validAfterTime: "2026-08-13T12:02:00Z" }),
    validKey({ validAfterTime: "invalid" }),
  ];
  for (const key of attacks) {
    await assert.rejects(() => observedReader(async () => keyResponse(key))(observedArguments()));
  }
  await assert.rejects(() => observedReader(async () => keyResponse(validKey()))(
    observedArguments({ expected_disabled: "false" }),
  ), /expected_disabled/);
  await assert.rejects(() => observedReader(async () => keyResponse(validKey()))(
    observedArguments({ project_id: "-" }),
  ), /project_id/);
});

test("observed Google key transport rejects Date, status, bounds, UTF-8, and duplicate keys", async () => {
  const duplicate = JSON.stringify(validKey()).replace("{", `{"name":"duplicate",`);
  const responses = [
    () => keyResponse(validKey(), { date: "" }),
    () => keyResponse(validKey(), { date: "invalid" }),
    () => keyResponse(validKey(), { status: 201 }),
    () => keyResponse(Buffer.from([0xff])),
    () => keyResponse(duplicate),
    () => keyResponse(validKey(), { headers: { "content-length": "64001" } }),
    () => keyResponse({ padding: "x".repeat(64_001) }),
  ];
  for (const response of responses) {
    await assert.rejects(() => observedReader(async () => response())(observedArguments()));
  }
});

test("observed Google key transport returns only static errors for hostile boundaries", async () => {
  const marker = `google-key-marker-${"x".repeat(32)}`;
  const assertStatic = async (reader, pattern) => {
    let error;
    try { await reader(observedArguments()); } catch (caught) { error = caught; }
    assert.ok(error);
    assert.match(error.message, pattern);
    assert.equal(error.message.includes(marker), false);
  };
  await assertStatic(observedReader(async () => { throw new Error(marker); }), /transport failed/);
  await assertStatic(observedReader(async () => keyResponse(validKey()), {
    getClient: async () => { throw new Error(marker); },
  }), /transport failed/);
  await assertStatic(observedReader(async () => ({
    status: 200,
    ok: true,
    get headers() { throw new Error(marker); },
    body: null,
  })), /primitives are invalid/);
  await assertStatic(observedReader(async () => ({
    status: 200,
    ok: true,
    headers: { get: (name) => name === "date" ? "Thu, 13 Aug 2026 12:01:00 GMT" : null },
    body: { getReader: () => ({
      read: async () => { throw new Error(marker); },
      cancel: async () => { throw new Error(marker); },
    }) },
  })), /body is invalid/);
});

test("observed Google key reader snapshots response primitives before body awaits", async () => {
  const headers = new Headers({ date: "Thu, 13 Aug 2026 12:01:00 GMT" });
  let status = 200;
  let reads = 0;
  const bytes = Buffer.from(JSON.stringify(validKey()));
  const result = await observedReader(async () => ({
    get status() { return status; },
    get ok() { return status === 200; },
    headers,
    body: { getReader: () => ({
      read: async () => {
        reads += 1;
        status = 500;
        headers.set("date", "invalid-after-capture");
        return reads === 1 ? { done: false, value: bytes } : { done: true, value: undefined };
      },
      cancel: async () => {},
    }) },
  }))(observedArguments());
  assert.equal(result.observedAt, "2026-08-13T12:01:00.000Z");
  assert.equal(result.key.name, keyName);
});
