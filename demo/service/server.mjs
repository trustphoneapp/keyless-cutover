import { createServer } from "node:http";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function canaryPayload(env = process.env) {
  return {
    service: env.K_SERVICE ?? "local",
    revision: env.K_REVISION ?? "local",
    release: env.RELEASE ?? "unset",
  };
}

export function handleCanaryRequest(request, response, env = process.env) {
  const method = request?.method;
  const url = request?.url;
  if (method === "GET" && url === "/healthz") {
    response.writeHead(204, { "cache-control": "no-store" });
    response.end();
    return;
  }
  if (method === "GET" && url === "/") {
    const payload = `${JSON.stringify(canaryPayload(env))}\n`;
    response.writeHead(200, {
      "content-type": "application/json",
      "cache-control": "no-store",
      "content-length": Buffer.byteLength(payload),
    });
    response.end(payload);
    return;
  }
  response.writeHead(404, { "cache-control": "no-store" });
  response.end();
}

function main() {
  const port = Number(process.env.PORT ?? 8080);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("PORT is invalid");
  createServer((request, response) => handleCanaryRequest(request, response)).listen(port, "0.0.0.0");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
