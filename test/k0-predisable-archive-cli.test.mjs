import assert from "node:assert/strict";
import { execFile as execFileCallback, spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, readdir, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { test } from "node:test";

import { canonicalJson } from "../src/evidence-artifact.mjs";
import { verifyK0PreDisableArchive } from "../src/k0-predisable-archive.mjs";
import { validPreDisableArchiveInput } from "./support/k0-predisable.mjs";

const execFile = promisify(execFileCallback);
const CLI = resolve("bin/k0-predisable-archive.mjs");

async function fixtureDirectory() {
  const root = await mkdtemp(join(tmpdir(), "k0-predisable-"));
  const { plan, artifacts } = await validPreDisableArchiveInput();
  const planPath = join(root, "plan.json");
  const artifactDirectory = join(root, "artifacts");
  await writeFile(planPath, canonicalJson(plan), { mode: 0o600 });
  await mkdir(artifactDirectory, { mode: 0o700 });
  for (const [id, bytes] of artifacts) await writeFile(join(artifactDirectory, `${id}.json`), bytes, { mode: 0o600 });
  return { root, plan, artifacts, planPath, artifactDirectory };
}

async function run(paths) {
  return execFile(process.execPath, [CLI, ...paths], { timeout: 5_000 });
}

async function expectStaticFailure(paths) {
  try {
    await run(paths);
    assert.fail("command unexpectedly succeeded");
  } catch (error) {
    assert.equal(error.stdout, "");
    assert.equal(error.stderr, "K0 pre-disable archive command failed\n");
  }
}

test("archive CLI writes one canonical verified deterministic archive with private modes", async () => {
  const fixture = await fixtureDirectory();
  try {
    const firstOutput = join(fixture.root, "output-one");
    const secondOutput = join(fixture.root, "output-two");
    const first = await run([fixture.planPath, fixture.artifactDirectory, firstOutput]);
    const second = await run([fixture.planPath, fixture.artifactDirectory, secondOutput]);
    assert.equal(first.stdout, "K0 pre-disable archive created\n");
    assert.equal(first.stderr, "");
    assert.deepEqual(second, first);
    const firstBytes = await readFile(join(firstOutput, "predisable-archive.json"));
    const secondBytes = await readFile(join(secondOutput, "predisable-archive.json"));
    assert.deepEqual(firstBytes, secondBytes);
    assert.equal(await verifyK0PreDisableArchive(firstBytes), true);
    assert.equal((await stat(firstOutput)).mode & 0o777, 0o700);
    assert.equal((await stat(join(firstOutput, "predisable-archive.json"))).mode & 0o777, 0o600);
    assert.deepEqual(await readdir(firstOutput), ["predisable-archive.json"]);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("archive CLI rejects existing targets and concurrent writers without partial alternatives", async () => {
  const fixture = await fixtureDirectory();
  try {
    for (const kind of ["directory", "file", "symlink"]) {
      const output = join(fixture.root, `existing-${kind}`);
      if (kind === "directory") await mkdir(output);
      if (kind === "file") await writeFile(output, "keep");
      if (kind === "symlink") await symlink(fixture.artifactDirectory, output);
      await expectStaticFailure([fixture.planPath, fixture.artifactDirectory, output]);
    }

    const output = join(fixture.root, "concurrent");
    const results = await Promise.allSettled([
      run([fixture.planPath, fixture.artifactDirectory, output]),
      run([fixture.planPath, fixture.artifactDirectory, output]),
    ]);
    assert.equal(results.filter(({ status }) => status === "fulfilled").length, 1);
    assert.equal(results.filter(({ status }) => status === "rejected").length, 1);
    assert.equal(await verifyK0PreDisableArchive(await readFile(join(output, "predisable-archive.json"))), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("archive CLI rejects malformed plans and non-exact artifact directories with no output", async () => {
  const cases = [
    async (fixture) => writeFile(fixture.planPath, ` ${canonicalJson(fixture.plan)}`),
    async (fixture) => writeFile(fixture.planPath, "{"),
    async (fixture) => writeFile(fixture.planPath, Buffer.alloc(700 * 1024 + 1)),
    async (fixture) => writeFile(join(fixture.artifactDirectory, "extra.json"), "{}\n"),
    async (fixture) => unlink(join(fixture.artifactDirectory, `${fixture.plan.evidence[0].id}.json`)),
    async (fixture) => {
      const path = join(fixture.artifactDirectory, `${fixture.plan.evidence[0].id}.json`);
      await unlink(path);
      await symlink(fixture.planPath, path);
    },
    async (fixture) => {
      const path = join(fixture.artifactDirectory, `${fixture.plan.evidence[0].id}.json`);
      const token = `gh${"p"}_${"x".repeat(24)}`;
      await writeFile(path, token);
    },
  ];
  for (const arrange of cases) {
    const fixture = await fixtureDirectory();
    try {
      const output = join(fixture.root, "output");
      await arrange(fixture);
      await expectStaticFailure([fixture.planPath, fixture.artifactDirectory, output]);
      await assert.rejects(() => stat(output), { code: "ENOENT" });
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("archive CLI rejects plan, artifact, and output symlinks and FIFOs without hanging", async (t) => {
  if (spawnSync("mkfifo", ["--help"], { stdio: "ignore" }).error?.code === "ENOENT") {
    t.skip("mkfifo is unavailable");
    return;
  }
  const modes = ["plan-symlink", "plan-fifo", "artifact-fifo"];
  for (const mode of modes) {
    const fixture = await fixtureDirectory();
    try {
      let planPath = fixture.planPath;
      if (mode === "plan-symlink") {
        planPath = join(fixture.root, "plan-link.json");
        await symlink(fixture.planPath, planPath);
      }
      if (mode === "plan-fifo") {
        await unlink(fixture.planPath);
        assert.equal(spawnSync("mkfifo", [fixture.planPath]).status, 0);
      }
      if (mode === "artifact-fifo") {
        const path = join(fixture.artifactDirectory, `${fixture.plan.evidence[0].id}.json`);
        await unlink(path);
        assert.equal(spawnSync("mkfifo", [path]).status, 0);
      }
      const output = join(fixture.root, "output");
      await expectStaticFailure([planPath, fixture.artifactDirectory, output]);
      await assert.rejects(() => stat(output), { code: "ENOENT" });
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});
