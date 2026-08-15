import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { lstat, mkdtemp, mkdir, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { canonicalJson } from "../src/evidence-artifact.mjs";
import { validK0BundleInput } from "./fixtures/k0-bundle.mjs";

const CLI = resolve("bin/k0-bundle.mjs");

function run(...args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
}

function runAsync(...args) {
  return new Promise((resolveRun) => {
    const child = spawn(process.execPath, [CLI, ...args]);
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (value) => { stdout += value; });
    child.stderr.setEncoding("utf8").on("data", (value) => { stderr += value; });
    child.on("close", (status) => resolveRun({ status, stdout, stderr }));
  });
}

test("local bundle CLI assembles and verifies without overwriting or fetching", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "keyless-k0-cli-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const inputPath = join(root, "input.json");
  const bundlePath = join(root, "bundle");
  await writeFile(inputPath, canonicalJson(validK0BundleInput()));

  const assembled = run("assemble", inputPath, bundlePath);
  assert.equal(assembled.status, 0, assembled.stderr);
  assert.equal(assembled.stdout, "K0 bundle assembled\n");
  const verified = run("verify", bundlePath);
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(verified.stdout, "K0 bundle verified\n");

  const manifest = JSON.parse(await readFile(join(bundlePath, "manifest.json")));
  assert.deepEqual((await Promise.all(manifest.evidence.map(async ({ id }) => readFile(
    join(bundlePath, "artifacts", `${id}.json`),
  )))).length, manifest.evidence.length);

  const second = run("assemble", inputPath, bundlePath);
  assert.notEqual(second.status, 0);
  assert.equal(second.stderr, "K0 bundle command failed\n");
  assert.equal(run("verify", bundlePath).status, 0);
});

test("concurrent assembly creates one complete target and one static failure", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "keyless-k0-cli-race-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const inputPath = join(root, "input.json");
  const bundlePath = join(root, "bundle");
  await writeFile(inputPath, canonicalJson(validK0BundleInput()));
  const results = await Promise.all([
    runAsync("assemble", inputPath, bundlePath),
    runAsync("assemble", inputPath, bundlePath),
  ]);
  assert.deepEqual(results.map(({ status }) => status).sort(), [0, 1]);
  assert.equal(results.find(({ status }) => status === 1).stderr, "K0 bundle command failed\n");
  assert.equal(run("verify", bundlePath).status, 0);
});

test("local bundle CLI rejects missing, extra, symlinked, and noncanonical bundle files", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "keyless-k0-cli-files-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const inputPath = join(root, "input.json");
  await writeFile(inputPath, canonicalJson(validK0BundleInput()));

  const cases = [
    ["extra", async (bundle) => writeFile(join(bundle, "artifacts", "extra.json"), "{}")],
    ["missing", async (bundle) => unlink(join(bundle, "artifacts", "E001.json"))],
    ["symlink", async (bundle) => {
      await unlink(join(bundle, "artifacts", "E001.json"));
      await symlink(join(bundle, "manifest.json"), join(bundle, "artifacts", "E001.json"));
    }],
    ["noncanonical", async (bundle) => {
      const path = join(bundle, "manifest.json");
      await writeFile(path, Buffer.concat([await readFile(path), Buffer.from("\n")]));
    }],
    ["truncated", async (bundle) => {
      const path = join(bundle, "artifacts", "E001.json");
      const bytes = await readFile(path);
      await writeFile(path, bytes.subarray(0, bytes.length - 1));
    }],
    ["oversize", async (bundle) => writeFile(join(bundle, "artifacts", "E001.json"), Buffer.alloc(512_001, 0x20))],
  ];
  for (const [name, mutate] of cases) {
    const bundle = join(root, `bundle-${name}`);
    assert.equal(run("assemble", inputPath, bundle).status, 0);
    await mutate(bundle);
    const result = run("verify", bundle);
    assert.notEqual(result.status, 0, name);
    assert.equal(result.stderr, "K0 bundle command failed\n");
  }
});

test("local bundle CLI leaves no output for malformed, oversize, or existing targets", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "keyless-k0-cli-fail-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const malformed = join(root, "malformed.json");
  const oversize = join(root, "oversize.json");
  await writeFile(malformed, `{${["ghp", "not-a-real-token"].join("_")}`);
  await writeFile(oversize, Buffer.alloc(6_000_001, 0x20));
  for (const [input, output] of [
    [malformed, join(root, "malformed-output")],
    [oversize, join(root, "oversize-output")],
  ]) {
    const result = run("assemble", input, output);
    assert.notEqual(result.status, 0);
    assert.equal(result.stderr, "K0 bundle command failed\n");
    assert.equal(result.stdout, "");
    await assert.rejects(lstat(output));
  }

  const input = join(root, "valid.json");
  await writeFile(input, canonicalJson(validK0BundleInput()));
  const existingDirectory = join(root, "existing-directory");
  const existingFile = join(root, "existing-file");
  const existingSymlink = join(root, "existing-symlink");
  await mkdir(existingDirectory);
  await writeFile(join(existingDirectory, "marker"), "preserved");
  await writeFile(existingFile, "preserved");
  await symlink(existingFile, existingSymlink);
  for (const existing of [existingDirectory, existingFile, existingSymlink]) {
    const result = run("assemble", input, existing);
    assert.notEqual(result.status, 0);
    assert.equal(result.stderr, "K0 bundle command failed\n");
  }
  assert.equal(await readFile(join(existingDirectory, "marker"), "utf8"), "preserved");
  assert.equal(await readFile(existingFile, "utf8"), "preserved");
});

test("local bundle CLI rejects a FIFO input without blocking or creating output", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "keyless-k0-cli-fifo-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const fifoPath = join(root, "input.fifo");
  const outputPath = join(root, "output");
  const created = spawnSync("mkfifo", [fifoPath], { encoding: "utf8" });
  if (created.error?.code === "ENOENT") {
    t.skip("mkfifo is unavailable");
    return;
  }
  assert.equal(created.status, 0, created.stderr);
  const result = spawnSync(process.execPath, [CLI, "assemble", fifoPath, outputPath], {
    encoding: "utf8",
    timeout: 2_000,
    killSignal: "SIGKILL",
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "K0 bundle command failed\n");
  await assert.rejects(lstat(outputPath));
});

test("local bundle CLI refuses duplicate JSON keys on assemble input", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "keyless-k0-cli-dupe-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const inputPath = join(root, "input.json");
  const bundlePath = join(root, "bundle");
  await writeFile(inputPath, '{"manifest":{},"manifest":{},"evidence":[]}\n');
  const result = run("assemble", inputPath, bundlePath);
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "K0 bundle command failed\n");
  await assert.rejects(lstat(bundlePath));
});
