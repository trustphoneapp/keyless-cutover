#!/usr/bin/env node

import { Firestore } from "@google-cloud/firestore";

import { FirestoreChallengeStore } from "../src/firestore-challenge-store.mjs";
import { createGoogleKeyReader } from "../src/google-key-reader.mjs";
import { collectProofV2, issueProofV2, verifyAndConsumeProofV2 } from "../src/proofv2-operator.mjs";

const COMMANDS = new Set(["issue", "verify"]);
const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}$/;
const RUN_ID = /^\d+$/;
const WORKFLOW = /^\.github\/workflows\/[A-Za-z0-9._/-]+\.ya?ml$/;
const SERVICE_ACCOUNT = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;
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
    if (values[name] === undefined) throw new Error(`--${name} is required`);
  }
  return { command, values };
}

function requireBounded(value, name, pattern) {
  if (typeof value !== "string" || value.length < 1 || value.length > 512
      || /[\r\n]/.test(value) || value.trim() !== value || (pattern && !pattern.test(value))) {
    throw new Error(`--${name} is invalid`);
  }
  return value;
}

function validateIssueArguments(values) {
  requireBounded(values["project-id"], "project-id", PROJECT_ID);
  requireBounded(values["migration-id"], "migration-id");
  requireBounded(values["owner-id"], "owner-id", RUN_ID);
  requireBounded(values["repository-id"], "repository-id", RUN_ID);
  requireBounded(values["workflow-path"], "workflow-path", WORKFLOW);
  requireBounded(values["client-email"], "client-email", SERVICE_ACCOUNT);
  return values;
}

function validateVerifyArguments(values) {
  requireBounded(values["project-id"], "project-id", PROJECT_ID);
  requireBounded(values.owner, "owner", OWNER);
  requireBounded(values.repository, "repository", REPOSITORY);
  requireBounded(values["run-id"], "run-id", RUN_ID);
  requireBounded(values["workflow-path"], "workflow-path", WORKFLOW);
  return values;
}

function store(projectId) {
  return new FirestoreChallengeStore({ firestore: new Firestore({ projectId }) });
}

async function main() {
  const { command, values } = argumentsFor(process.argv.slice(2));
  if (command === "issue") {
    const approved = validateIssueArguments(values);
    const result = await issueProofV2({
      challengeStore: store(approved["project-id"]),
      scope: {
        migration_id: approved["migration-id"],
        owner_id: approved["owner-id"],
        repository_id: approved["repository-id"],
        workflow_path: approved["workflow-path"],
        event_name: "workflow_dispatch",
        ref: "refs/heads/main",
        environment: "production",
        client_email: approved["client-email"],
      },
    });
    process.stdout.write(`${JSON.stringify(result.dispatch_inputs, null, 2)}\n`);
    return;
  }

  const approved = validateVerifyArguments(values);
  const token = process.env.KEYLESS_GITHUB_TOKEN;
  if (!token) throw new Error("KEYLESS_GITHUB_TOKEN is required and must never be passed as an argument");
  const challengeStore = store(approved["project-id"]);
  const collected = await collectProofV2({
    owner: approved.owner,
    repository: approved.repository,
    runId: approved["run-id"],
    workflowPath: approved["workflow-path"],
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
