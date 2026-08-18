import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

const workflowDirectory = new URL("../.github/workflows/", import.meta.url);

const allowedAdkPeerProblems = new Set([
  "missing: @mikro-orm/mariadb@^6.6.6, required by @google/adk@1.6.0",
  "missing: @mikro-orm/mssql@^6.6.6, required by @google/adk@1.6.0",
  "missing: @mikro-orm/mysql@^6.6.6, required by @google/adk@1.6.0",
  "missing: @mikro-orm/postgresql@^6.6.6, required by @google/adk@1.6.0",
  "missing: @mikro-orm/sqlite@^6.6.6, required by @google/adk@1.6.0",
]);

test("installed dependency tree has no unreviewed problems", () => {
  const result = spawnSync("npm", ["ls", "--all", "--json"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
  });
  assert.notEqual(result.error?.code, "ENOENT", "npm is required for the dependency preflight");
  const tree = JSON.parse(result.stdout);
  const unreviewed = (tree.problems ?? []).filter((problem) => !allowedAdkPeerProblems.has(problem));
  assert.deepEqual(unreviewed, []);
  assert.ok((tree.problems ?? []).every((problem) => problem.startsWith("missing: @mikro-orm/")));
});

test("every external GitHub Action is pinned to a full commit SHA", async () => {
  for (const file of await readdir(workflowDirectory)) {
    if (!/\.ya?ml$/.test(file)) continue;
    const source = await readFile(new URL(file, workflowDirectory), "utf8");
    for (const match of source.matchAll(/^\s*- uses:\s+([^\s#]+)/gm)) {
      if (match[1].startsWith("./")) continue;
      assert.match(match[1], /^[^@\s]+@[a-f0-9]{40}$/, `${file} contains an unpinned action`);
    }
  }
});

test("ProofV2 workflow preserves the reviewed runtime and artifact boundary", async () => {
  const source = await readFile(new URL("k0-proof-v2.yml", workflowDirectory), "utf8");
  assert.match(source, /^\s+environment: production$/m);
  assert.match(source, /^\s+timeout-minutes: 5$/m);
  assert.match(source, /^\s+persist-credentials: false$/m);
  assert.match(source, /actions\/setup-node@[a-f0-9]{40}/);
  assert.match(source, /^\s+node-version: 24$/m);
  assert.match(source, /node src\/key-proof\.mjs generate keyless-proof-v2\.json/);
  assert.match(source, /^\s+path: keyless-proof-v2\.json$/m);
  assert.doesNotMatch(source, /^\s+path: \./m);
  assert.doesNotMatch(source, /include-hidden-files:\s*true/);

  execFileSync("node", ["--check", "src/key-proof.mjs"], {
    cwd: new URL("..", import.meta.url),
    stdio: "pipe",
  });
});

test("runtime containers are digest-pinned and exclude package-manager tooling", async () => {
  const dockerfiles = ["agent/Dockerfile", "console/Dockerfile", "demo/service/Dockerfile"];
  for (const file of dockerfiles) {
    const source = await readFile(new URL(`../${file}`, import.meta.url), "utf8");
    for (const line of source.match(/^FROM .+$/gm) ?? []) {
      assert.match(line, /^FROM node:24-alpine@sha256:[a-f0-9]{64}(?: AS \w+)?$/);
    }
    assert.match(source, /\/usr\/local\/lib\/node_modules\/npm/);
    assert.match(source, /\/usr\/local\/lib\/node_modules\/corepack/);
  }
  const agent = await readFile(new URL("../agent/Dockerfile", import.meta.url), "utf8");
  assert.match(agent, /npm ci --omit=dev --legacy-peer-deps --ignore-scripts/);
});

test("console image import graph is dependency-free", async () => {
  // console/Dockerfile ships src/ and console/ with no node_modules; any bare
  // specifier reachable from the server entry crashes the container at startup.
  const { dirname, resolve } = await import("node:path");
  const seen = new Set();
  const external = [];
  const walk = async (file) => {
    if (seen.has(file)) return;
    seen.add(file);
    const source = await readFile(file, "utf8");
    for (const [, specifier] of source.matchAll(/^import[^"']*["']([^"']+)["']/gm)) {
      if (specifier.startsWith("node:")) continue;
      if (specifier.startsWith(".")) await walk(resolve(dirname(file), specifier));
      else external.push(`${specifier} <- ${file}`);
    }
  };
  await walk(new URL("../console/server.mjs", import.meta.url).pathname);
  assert.deepEqual(external, []);
});
