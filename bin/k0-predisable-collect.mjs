#!/usr/bin/env node

import { lstat, mkdir, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { Firestore } from "@google-cloud/firestore";
import { GoogleAuth } from "google-auth-library";

import { FirestoreChallengeStore } from "../src/firestore-challenge-store.mjs";
import { readBoundedFile } from "../src/k0-bundle-files.mjs";
import {
  collectK0PreDisable,
  observeK0ForbiddenBefore,
  parseK0PreDisableCollectPlan,
} from "../src/k0-predisable-collect.mjs";

const MAX_PLAN = 32 * 1024;
const MAX_RECEIPT = 64 * 1024;
const MAX_OBSERVATION = 8 * 1024;

async function writeOutputs(outputs, directory) {
  let created;
  try {
    await mkdir(directory, { mode: 0o700 });
    created = await lstat(directory);
    for (const [name, bytes] of [
      ["bundle-input.json", outputs.bundleInputBytes],
      ["archive-plan.json", outputs.archivePlanBytes],
      ["checkpoint-receipt.json", outputs.checkpointReceiptBytes],
    ]) {
      await writeFile(join(directory, name), bytes, { flag: "wx", mode: 0o600 });
    }
    // The artifact directory bin/k0-predisable-archive.mjs requires: one <id>.json file per
    // evidence entry, exactly matching archive-plan.json's evidence list.
    const artifactDirectory = join(directory, "artifacts");
    await mkdir(artifactDirectory, { mode: 0o700 });
    for (const [id, bytes] of outputs.artifacts) {
      await writeFile(join(artifactDirectory, `${id}.json`), bytes, { flag: "wx", mode: 0o600 });
    }
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

function readOnlyAuth() {
  return new GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform.read-only"] });
}

// observe-forbidden must run BEFORE the first hostile probe: the verifier requires this observation
// strictly before H8 started, and the collect plan cannot be written until H8 exists.
async function main(argv) {
  const [command, ...args] = argv;
  if (command === "observe-forbidden" && args.length === 2) {
    const [planPath, observationPath] = args.map((path) => resolve(path));
    const bytes = await observeK0ForbiddenBefore(await readBoundedFile(planPath, MAX_PLAN), {
      googleAuth: readOnlyAuth(),
    });
    await writeFile(observationPath, bytes, { flag: "wx", mode: 0o600 });
    process.stdout.write("K0 forbidden-before observation recorded\n");
    return;
  }
  if (command === "collect" && args.length === 4) {
    const [planPath, receiptPath, observationPath, outputDirectory] = args.map((path) => resolve(path));
    const token = process.env.KEYLESS_GITHUB_TOKEN;
    if (!token) throw new Error("KEYLESS_GITHUB_TOKEN is required and must never be passed as an argument");
    const planBytes = await readBoundedFile(planPath, MAX_PLAN);
    const plan = parseK0PreDisableCollectPlan(planBytes);
    const outputs = await collectK0PreDisable(planBytes, {
      installationToken: token,
      googleAuth: readOnlyAuth(),
      challengeStore: new FirestoreChallengeStore({
        firestore: new Firestore({ projectId: plan.scope.project_id }),
      }),
      operatorReceiptBytes: await readBoundedFile(receiptPath, MAX_RECEIPT),
      forbiddenBeforeBytes: await readBoundedFile(observationPath, MAX_OBSERVATION),
    });
    await writeOutputs(outputs, outputDirectory);
    process.stdout.write("K0 pre-disable evidence collected\n");
    return;
  }
  throw new Error("invalid command");
}

main(process.argv.slice(2)).catch(() => {
  process.stderr.write("K0 pre-disable collect command failed\n");
  process.exitCode = 1;
});
