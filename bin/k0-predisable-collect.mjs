#!/usr/bin/env node

import { lstat, mkdir, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { Firestore } from "@google-cloud/firestore";
import { GoogleAuth } from "google-auth-library";

import { FirestoreChallengeStore } from "../src/firestore-challenge-store.mjs";
import { readBoundedFile } from "../src/k0-bundle-files.mjs";
import { collectK0PreDisable, parseK0PreDisableCollectPlan } from "../src/k0-predisable-collect.mjs";

const MAX_PLAN = 32 * 1024;
const MAX_RECEIPT = 64 * 1024;

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
  const [planPath, receiptPath, outputDirectory] = argv.map((path) => resolve(path));
  const token = process.env.KEYLESS_GITHUB_TOKEN;
  if (!token) throw new Error("KEYLESS_GITHUB_TOKEN is required and must never be passed as an argument");
  const planBytes = await readBoundedFile(planPath, MAX_PLAN);
  const plan = parseK0PreDisableCollectPlan(planBytes);
  const outputs = await collectK0PreDisable(planBytes, {
    installationToken: token,
    googleAuth: new GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform.read-only"] }),
    challengeStore: new FirestoreChallengeStore({
      firestore: new Firestore({ projectId: plan.scope.project_id }),
    }),
    operatorReceiptBytes: await readBoundedFile(receiptPath, MAX_RECEIPT),
  });
  await writeOutputs(outputs, outputDirectory);
  process.stdout.write("K0 pre-disable evidence collected\n");
}

main(process.argv.slice(2)).catch(() => {
  process.stderr.write("K0 pre-disable collect command failed\n");
  process.exitCode = 1;
});
