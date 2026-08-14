import { constants } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import { join } from "node:path";

import { canonicalJson } from "./evidence-artifact.mjs";
import { verifyK0Bundle } from "./k0-bundle.mjs";

const MAX_MANIFEST = 1_000_000;
const MAX_ARTIFACT = 512_000;
const MAX_ARTIFACTS = 5_000_000;

export async function readBoundedFile(path, limit) {
  const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > limit) throw new Error("bounded file is invalid");
    const bytes = await handle.readFile();
    if (bytes.length > limit) throw new Error("bounded file is invalid");
    return bytes;
  } finally {
    await handle.close();
  }
}

async function exactDirectory(path) {
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("bundle directory is invalid");
}

export async function readExactArtifactDirectory(directory, evidence) {
  await exactDirectory(directory);
  const files = await readdir(directory, { withFileTypes: true });
  const expected = [...new Set((evidence ?? []).map(({ id }) => `${id}.json`))].sort();
  const actual = files.map(({ name }) => name).sort();
  if (files.some((entry) => !entry.isFile()) || actual.length !== expected.length
      || actual.some((name, index) => name !== expected[index])) {
    throw new Error("bundle artifacts do not exactly match the manifest");
  }
  const artifacts = new Map();
  let total = 0;
  for (const name of expected) {
    const id = name.slice(0, -".json".length);
    const bytes = await readBoundedFile(join(directory, name), MAX_ARTIFACT);
    total += bytes.length;
    if (total > MAX_ARTIFACTS) throw new Error("bundle artifacts exceed the size budget");
    artifacts.set(id, bytes);
  }
  return artifacts;
}

export async function readK0BundleDirectory(directory) {
  await exactDirectory(directory);
  const top = await readdir(directory, { withFileTypes: true });
  if (top.length !== 2
      || !top.some((entry) => entry.name === "manifest.json" && entry.isFile())
      || !top.some((entry) => entry.name === "artifacts" && entry.isDirectory())) {
    throw new Error("bundle directory entries are invalid");
  }
  const manifestBytes = await readBoundedFile(join(directory, "manifest.json"), MAX_MANIFEST);
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    throw new Error("bundle manifest is not JSON");
  }
  if (manifestBytes.toString("utf8") !== canonicalJson(manifest)) throw new Error("bundle manifest is not canonical");

  const artifactDirectory = join(directory, "artifacts");
  const artifacts = await readExactArtifactDirectory(artifactDirectory, manifest.evidence);
  await verifyK0Bundle({ manifest, artifacts });
  return { manifest, manifestBytes, artifacts };
}
