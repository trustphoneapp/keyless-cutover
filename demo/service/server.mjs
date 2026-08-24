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

function main() {
  const port = Number(process.env.PORT ?? 8080);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("PORT is invalid");
  createServer((request, response) => {
    response.writeHead(request.url === "/_health" ? 204 : 200, {
      "content-type": "application/json",
      "cache-control": "no-store",
    });
    response.end(request.url === "/_health" ? undefined : `${JSON.stringify(canaryPayload())}\n`);
  }).listen(port, "0.0.0.0");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
