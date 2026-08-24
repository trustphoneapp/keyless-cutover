#!/usr/bin/env node

import { lstat, mkdir, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import { readBoundedFile, readExactArtifactDirectory } from "../src/k0-bundle-files.mjs";
import {
  createK0PreDisableArchive,
  parseK0PreDisableArchivePlanBytes,
  verifyK0PreDisableArchive,
} from "../src/k0-predisable-archive.mjs";

const MAX_ARCHIVE = 700 * 1024;

async function writeArchive(archiveBytes, directory) {
  let created;
  try {
    await mkdir(directory, { mode: 0o700 });
    created = await lstat(directory);
    const path = join(directory, "predisable-archive.json");
    await writeFile(path, archiveBytes, { flag: "wx", mode: 0o600 });
    await verifyK0PreDisableArchive(await readBoundedFile(path, MAX_ARCHIVE));
  } catch (error) {
    if (created) {
      try {
        const current = await lstat(directory);
        if (current.isDirectory() && !current.isSymbolicLink()
            && current.dev === created.dev && current.ino === created.ino) {
          await rm(directory, { recursive: true });
        }
      } catch {
        // Failure remains closed if cleanup races or the target disappears.
      }
    }
    throw error;
  }
}

async function main(argv) {
  if (argv.length !== 3) throw new Error("invalid command");
  const [planPath, artifactDirectory, outputDirectory] = argv.map((path) => resolve(path));
  const plan = parseK0PreDisableArchivePlanBytes(await readBoundedFile(planPath, MAX_ARCHIVE));
  const artifacts = await readExactArtifactDirectory(artifactDirectory, plan.evidence);
  const { archiveBytes } = await createK0PreDisableArchive(plan, artifacts);
  await writeArchive(archiveBytes, outputDirectory);
  process.stdout.write("K0 pre-disable archive created\n");
}

main(process.argv.slice(2)).catch(() => {
  process.stderr.write("K0 pre-disable archive command failed\n");
  process.exitCode = 1;
});
