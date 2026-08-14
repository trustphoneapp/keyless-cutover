#!/usr/bin/env node

import { lstat, mkdir, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import { assembleK0Bundle } from "../src/k0-bundle.mjs";
import { readBoundedFile, readK0BundleDirectory } from "../src/k0-bundle-files.mjs";

const MAX_INPUT = 6_000_000;

async function writeBundle(bundle, directory) {
  let created;
  try {
    await mkdir(directory, { mode: 0o700 });
    created = await lstat(directory);
    await mkdir(join(directory, "artifacts"), { mode: 0o700 });
    await writeFile(join(directory, "manifest.json"), bundle.manifestBytes, { flag: "wx", mode: 0o600 });
    for (const [id, bytes] of bundle.artifacts) {
      await writeFile(join(directory, "artifacts", `${id}.json`), bytes, { flag: "wx", mode: 0o600 });
    }
    await readK0BundleDirectory(directory);
  } catch (error) {
    if (created) {
      try {
        const current = await lstat(directory);
        if (current.isDirectory() && !current.isSymbolicLink()
            && current.dev === created.dev && current.ino === created.ino) {
          await rm(directory, { recursive: true });
        }
      } catch {
        // The command still fails closed if cleanup raced or the target disappeared.
      }
    }
    throw error;
  }
}

async function main(argv) {
  const [command, ...paths] = argv;
  if (command === "assemble" && paths.length === 2) {
    const inputBytes = await readBoundedFile(resolve(paths[0]), MAX_INPUT);
    let input;
    try {
      input = JSON.parse(inputBytes.toString("utf8"));
    } catch {
      throw new Error("bundle input is not JSON");
    }
    const bundle = await assembleK0Bundle(input);
    await writeBundle(bundle, resolve(paths[1]));
    process.stdout.write("K0 bundle assembled\n");
    return;
  }
  if (command === "verify" && paths.length === 1) {
    await readK0BundleDirectory(resolve(paths[0]));
    process.stdout.write("K0 bundle verified\n");
    return;
  }
  throw new Error("invalid command");
}

main(process.argv.slice(2)).catch(() => {
  process.stderr.write("K0 bundle command failed\n");
  process.exitCode = 1;
});
