import { createServer as createHttpServer } from "node:http";
import { timingSafeEqual } from "node:crypto";

import { textLooksLikeCredential } from "../src/credential-scan.mjs";
import { rejectDuplicateJsonKeys } from "../src/observation-time.mjs";

const MAX_BODY_BYTES = 64 * 1024;
const API_TOKEN_HEADER = "x-keyless-api-token";

function authorized(request, apiToken) {
  const supplied = request.headers[API_TOKEN_HEADER];
  if (typeof supplied !== "string") return false;
  const expected = Buffer.from(apiToken);
  const actual = Buffer.from(supplied);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

async function body(request) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > MAX_BODY_BYTES) throw new Error("request is too large");
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (textLooksLikeCredential(text)) throw new Error("request contains credential-shaped material");
  rejectDuplicateJsonKeys(text);
  const value = JSON.parse(text);
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error("request body is invalid");
  }
  return value;
}

function send(response, status, value) {
  const payload = JSON.stringify(value);
  response.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(payload) });
  response.end(payload);
}

export function createKeylessAgentServer({ evidenceInvoker, recoveryInvoker, apiToken }) {
  if (typeof evidenceInvoker !== "function" || typeof recoveryInvoker !== "function") {
    throw new Error("agent invokers are required");
  }
  if (typeof apiToken !== "string" || apiToken.length < 32) throw new Error("KEYLESS_API_TOKEN is invalid");
  return createHttpServer(async (request, response) => {
    if (request.method === "GET" && request.url === "/healthz") {
      send(response, 200, { status: "ok", model: "gemini-3.5-flash", tools: 0 });
      return;
    }
    const invoker = request.url === "/v1/evidence" ? evidenceInvoker
      : request.url === "/v1/recovery" ? recoveryInvoker : null;
    if (request.method !== "POST" || !invoker) {
      send(response, 404, { error: "not_found" });
      return;
    }
    if (!authorized(request, apiToken)) {
      send(response, 401, { error: "unauthorized" });
      return;
    }
    try {
      send(response, 200, { output: await invoker(await body(request)) });
    } catch {
      send(response, 400, { error: "request_rejected" });
    }
  });
}
