import assert from "node:assert/strict";
import test from "node:test";

import { createGoogleKeyReader } from "../src/google-key-reader.mjs";

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
          disabled: false,
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

test("Google key reader rejects malformed identity before authentication", async () => {
  let called = false;
  const reader = createGoogleKeyReader({ auth: { getClient: async () => { called = true; } } });
  await assert.rejects(reader({ client_email: "bad", private_key_id: "a".repeat(40) }), /client_email/);
  assert.equal(called, false);
});
