#!/usr/bin/env node

import { Firestore } from "@google-cloud/firestore";

import { FirestoreChallengeStore } from "../src/firestore-challenge-store.mjs";
import { createGoogleKeyReader } from "../src/google-key-reader.mjs";
import { collectProofV2, issueProofV2, verifyAndConsumeProofV2 } from "../src/proofv2-operator.mjs";

const COMMANDS = new Set(["issue", "verify"]);
const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const ALLOWED = {
  issue: new Set(["project-id", "migration-id", "owner-id", "repository-id", "workflow-path", "client-email"]),
  verify: new Set(["project-id", "owner", "repository", "run-id", "workflow-path"]),
};

function argumentsFor(argv) {
  const [command, ...rest] = argv;
  if (!COMMANDS.has(command)) throw new Error("usage: proofv2-operator <issue|verify> --name value ...");
  if (rest.length % 2 !== 0) throw new Error("every option requires one value");
  const values = {};
  for (let index = 0; index < rest.length; index += 2) {
    const option = rest[index];
    if (!option.startsWith("--") || !ALLOWED[command].has(option.slice(2))) throw new Error(`unsupported option ${option}`);
    if (values[option.slice(2)] !== undefined) throw new Error(`duplicate option ${option}`);
    values[option.slice(2)] = rest[index + 1];
  }
  for (const name of ALLOWED[command]) {
    if (!values[name]) throw new Error(`--${name} is required`);
  }
  return { command, values };
}

function store(projectId) {
  if (!PROJECT_ID.test(projectId)) throw new Error("--project-id is invalid");
  return new FirestoreChallengeStore({ firestore: new Firestore({ projectId }) });
}

async function main() {
  const { command, values } = argumentsFor(process.argv.slice(2));
  if (command === "issue") {
    const result = await issueProofV2({
      challengeStore: store(values["project-id"]),
      scope: {
        migration_id: values["migration-id"],
        owner_id: values["owner-id"],
        repository_id: values["repository-id"],
        workflow_path: values["workflow-path"],
        event_name: "workflow_dispatch",
        ref: "refs/heads/main",
        environment: "production",
        client_email: values["client-email"],
      },
    });
    process.stdout.write(`${JSON.stringify(result.dispatch_inputs, null, 2)}\n`);
    return;
  }

  const token = process.env.KEYLESS_GITHUB_TOKEN;
  if (!token) throw new Error("KEYLESS_GITHUB_TOKEN is required and must never be passed as an argument");
  const challengeStore = store(values["project-id"]);
  const collected = await collectProofV2({
    owner: values.owner,
    repository: values.repository,
    runId: values["run-id"],
    workflowPath: values["workflow-path"],
    environment: "production",
    token,
  });
  const receipt = await verifyAndConsumeProofV2({
    challengeStore,
    proof: collected.proof,
    observed: collected.observed,
    getGoogleKey: createGoogleKeyReader(),
  });
  process.stdout.write(`${JSON.stringify({
    receipt,
    artifact_id: collected.artifact_id,
    artifact_name: collected.artifact_name,
    observed: collected.observed,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`ProofV2 operator failed: ${error.message}\n`);
  process.exitCode = 1;
});
