import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

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
    assert.match(source, /^HEALTHCHECK .+$/m);
    assert.match(source, /127\.0\.0\.1:8080\/healthz/);
  }
  const agent = await readFile(new URL("../agent/Dockerfile", import.meta.url), "utf8");
  assert.match(agent, /npm ci --omit=dev --legacy-peer-deps --ignore-scripts/);
  assert.match(agent, /r\.status===200/);
  assert.match(agent, /^COPY src \.\/src$/m);
  assert.match(agent, /^COPY agent \.\/agent$/m);
  const consoleImage = await readFile(new URL("../console/Dockerfile", import.meta.url), "utf8");
  assert.match(consoleImage, /r\.status===204/);
  const demo = await readFile(new URL("../demo/service/Dockerfile", import.meta.url), "utf8");
  assert.match(demo, /r\.status===204/);
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

test("CI workflow stays read-only with clean-install and high audit gates", async () => {
  const source = await readFile(new URL("ci.yml", workflowDirectory), "utf8");
  assert.match(source, /^permissions:\n\s+contents: read\n/m);
  assert.doesNotMatch(source, /pull_request_target:/);
  assert.doesNotMatch(source, /permissions:\s*write-all|contents:\s*write|id-token:\s*write/);
  assert.match(source, /npm ci --legacy-peer-deps --ignore-scripts/);
  assert.match(source, /npm audit --omit=dev --audit-level=high/);
  assert.match(source, /^\s+- run: npm test$/m);
  assert.match(source, /node-version: 24/);
});

test("package scripts stay local-only and do not expose merge or deploy shortcuts", async () => {
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.deepEqual(Object.keys(pkg.scripts).sort(), [
    "cutover", "plan:wif", "proofv2", "run:eval", "score:eval", "start:console", "test", "verify:k0",
  ]);
  assert.equal(pkg.scripts.test, "node --test");
  assert.equal(pkg.scripts["verify:k0"], "node bin/k0-bundle.mjs verify");
  assert.doesNotMatch(JSON.stringify(pkg.scripts), /gh |deploy|merge|kms|disable|dispatch/i);
  assert.equal(pkg.type, "module");
  assert.match(pkg.engines.node, />=22/);
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

test("bin, k0, and GitHub text inventory stays credential-free", async () => {
  const { assertCredentialFreeBytes } = await import("../src/credential-scan.mjs");
  const root = fileURLToPath(new URL("..", import.meta.url));
  const roots = ["bin", "k0", ".github"];
  const allowed = /\.(mjs|ya?ml|json|md|toml|txt)$/i;
  async function walk(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    const files = [];
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules") continue;
        files.push(...await walk(path));
        continue;
      }
      if (allowed.test(entry.name)) files.push(path);
    }
    return files;
  }
  for (const relative of roots) {
    for (const path of await walk(join(root, relative))) {
      const bytes = await readFile(path);
      assert.doesNotThrow(() => assertCredentialFreeBytes(bytes), path);
    }
  }
  const sample = Buffer.from('{"token":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}');
  assert.throws(() => assertCredentialFreeBytes(sample), /credential-shaped/);
});

test("committed workflow YAML inventory rejects privilege-widening shapes", async () => {
  const roots = [
    new URL("../.github/workflows/", import.meta.url),
    new URL("../k0/templates/", import.meta.url),
    new URL("../k0/fixtures/", import.meta.url),
  ];
  for (const directory of roots) {
    for (const file of await readdir(directory)) {
      if (!/\.ya?ml$/.test(file)) continue;
      const source = await readFile(new URL(file, directory), "utf8");
      assert.doesNotMatch(source, /^\s*pull_request_target\s*:/m, file);
      assert.doesNotMatch(source, /\bself-hosted\b/, file);
      assert.doesNotMatch(source, /permissions:\s*write-all/, file);
    }
  }

  const legacyAuth = await readFile(new URL("k0-legacy-auth-check.yml", workflowDirectory), "utf8");
  assert.match(legacyAuth, /^on:\n\s+workflow_dispatch:\n/m);
  assert.doesNotMatch(legacyAuth, /^\s+push:/m);
  assert.match(legacyAuth, /vars\.KEYLESS_K0_ENABLED == 'true'/);
  assert.match(legacyAuth, /test "\$ONLINE_OUTCOME" = failure/);
  assert.match(legacyAuth, /credentials_json:/);
  assert.doesNotMatch(legacyAuth, /id-token|GCP_WIF_PROVIDER/);

  const external = await readFile(new URL("../k0/templates/k0-external-hostile.yml", import.meta.url), "utf8");
  assert.match(external, /^\s+push:\n\s+branches: \[main\]\n\s+paths:\n\s+- demo\/release\.txt$/m);
  assert.match(external, /continue-on-error: true/);
  assert.match(external, /test "\$AUTH_OUTCOME" = failure/);
  assert.doesNotMatch(external, /secrets\./);
});
