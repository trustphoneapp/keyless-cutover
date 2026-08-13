import { GoogleAuth } from "google-auth-library";

const SERVICE_ACCOUNT_EMAIL = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;
const KEY_ID = /^[a-f0-9]{40}$/;

function exact(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
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
