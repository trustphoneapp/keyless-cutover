import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { githubReleaseMarker, githubWorkflowSnapshot } from "../src/github-workflow-snapshot.mjs";

function encoded(value, sha = "a".repeat(40)) {
  return { encoding: "base64", content: Buffer.from(value).toString("base64"), sha };
}

test("workflow snapshot rejects credential-shaped workflow bytes", () => {
  const clean = encoded("name: demo\n");
  const snapshot = githubWorkflowSnapshot(clean);
  assert.equal(snapshot.workflow_blob_sha, clean.sha);
  assert.equal(snapshot.workflow_sha256, createHash("sha256").update("name: demo\n").digest("hex"));
  assert.throws(() => githubWorkflowSnapshot(encoded("-----BEGIN PRIVATE KEY-----\n")), /invalid/);
  assert.throws(() => githubWorkflowSnapshot(encoded(`token ghp_${"a".repeat(36)}\n`)), /invalid/);
});

test("release marker allows one trailing newline and rejects multiline payloads", () => {
  assert.equal(githubReleaseMarker(encoded("legacy-2\n")), "legacy-2");
  assert.equal(githubReleaseMarker(encoded("wif-3")), "wif-3");
  assert.throws(() => githubReleaseMarker(encoded("legacy-2\nwif-1\n")), /invalid/);
  assert.throws(() => githubReleaseMarker(encoded("BAD")), /invalid/);
  assert.throws(() => githubReleaseMarker(encoded("legacy-2\0")), /invalid/);
});
