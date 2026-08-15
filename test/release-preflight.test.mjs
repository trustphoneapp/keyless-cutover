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

test("legacy baseline deploy is dispatch-only while H4 still watches release marker pushes", async () => {
  const deploy = await readFile(new URL("k0-deploy.yml", workflowDirectory), "utf8");
  const hostile = await readFile(new URL("k0-hostile-wrong-workflow.yml", workflowDirectory), "utf8");
  const template = await readFile(new URL("../k0/templates/k0-deploy.legacy.yml", import.meta.url), "utf8");

  assert.equal(deploy, template);
  assert.match(deploy, /^on:\n\s+workflow_dispatch:\n/m);
  assert.doesNotMatch(deploy, /^\s+push:/m);
  assert.match(deploy, /vars\.KEYLESS_K0_ENABLED == 'true' && github\.ref == 'refs\/heads\/main'/);
  assert.match(deploy, /secrets\.GCP_SERVICE_ACCOUNT_KEY/);
  assert.doesNotMatch(deploy, /id-token|GCP_WIF_PROVIDER/);

  assert.match(hostile, /^\s+push:\n\s+branches: \[main\]\n\s+paths:\n\s+- demo\/release\.txt$/m);
  assert.match(hostile, /vars\.KEYLESS_K0_ENABLED == 'true'/);
  assert.match(hostile, /hostile=H4/);
});

test("workflow and template action pins cover every external uses entry", async () => {
  const roots = [
    new URL("../.github/workflows/", import.meta.url),
    new URL("../k0/templates/", import.meta.url),
  ];
  for (const directory of roots) {
    for (const file of await readdir(directory)) {
      if (!/\.ya?ml$/.test(file)) continue;
      const source = await readFile(new URL(file, directory), "utf8");
      for (const match of source.matchAll(/^\s*-?\s*uses:\s+([^\s#]+)/gm)) {
        if (match[1].startsWith("./")) continue;
        assert.match(match[1], /^[^@\s]+@[a-f0-9]{40}$/, `${file} contains an unpinned action`);
      }
      assert.doesNotMatch(source, /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/);
      assert.doesNotMatch(source, /\bgh[pousr]_[A-Za-z0-9_]{20,}/);
      assert.doesNotMatch(source, /\bya29\.[A-Za-z0-9._-]{20,}/);
      assert.doesNotMatch(source, /\bAIza[0-9A-Za-z_-]{35}\b/);
    }
  }
});

test("published credential-free evidence artifacts reject credential shapes", async () => {
  const { assertCredentialFreeBytes } = await import("../src/credential-scan.mjs");
  const evidenceDirectory = new URL("../docs/evidence/", import.meta.url);
  for (const file of await readdir(evidenceDirectory)) {
    if (!/\.(json|md)$/.test(file)) continue;
    const bytes = await readFile(new URL(file, evidenceDirectory));
    assert.doesNotThrow(() => assertCredentialFreeBytes(bytes), file);
  }
});
