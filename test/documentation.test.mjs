import assert from "node:assert/strict";
import { readFile, readdir, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

async function markdownFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  return (await Promise.all(entries.map((entry) => {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) return markdownFiles(path);
    return entry.name.endsWith(".md") ? [path] : [];
  }))).flat();
}

test("public Markdown has no missing relative link targets", async () => {
  const files = [resolve(root, "README.md"), ...await markdownFiles(resolve(root, "docs"))];
  const missing = [];
  for (const file of files) {
    const text = await readFile(file, "utf8");
    for (const match of text.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
      const target = match[1].split("#")[0];
      if (!target || /^(https?:|mailto:)/.test(target)) continue;
      try {
        await stat(resolve(dirname(file), target));
      } catch {
        missing.push(`${file.slice(root.length + 1)} -> ${target}`);
      }
    }
  }
  assert.deepEqual(missing, []);
});

test("status docs stay fail-closed and reject stale RC-unpublished claims", async () => {
  const files = [
    "README.md",
    "docs/MASTER_PLAN.md",
    "docs/CLAIMS_AND_LIMITATIONS.md",
    "docs/EVALUATION.md",
    "docs/THREAT_MODEL.md",
    "docs/SECURITY_MODEL.md",
    "docs/ARCHITECTURE.md",
    "docs/evidence/REPOSITORY_PROTECTION_2026-08-15.md",
  ];
  const stale = [
    /RC is not committed\/published/i,
    /has not been committed, published/i,
    /current local RC/i,
    /Local issuer remains unpublished\/unrun/i,
    /but the RC is not committed\/published/i,
  ];
  const hits = [];
  for (const relative of files) {
    const text = await readFile(resolve(root, relative), "utf8");
    for (const pattern of stale) {
      if (pattern.test(text)) hits.push(`${relative} matches ${pattern}`);
    }
  }
  assert.deepEqual(hits, []);

  const readme = await readFile(resolve(root, "README.md"), "utf8");
  const master = await readFile(resolve(root, "docs/MASTER_PLAN.md"), "utf8");
  const claims = await readFile(resolve(root, "docs/CLAIMS_AND_LIMITATIONS.md"), "utf8");
  const evaluation = await readFile(resolve(root, "docs/EVALUATION.md"), "utf8");
  const protection = await readFile(
    resolve(root, "docs/evidence/REPOSITORY_PROTECTION_2026-08-15.md"),
    "utf8",
  );

  assert.match(readme, /NO-GO/);
  assert.match(master, /NO-GO/);
  assert.match(claims, /complete claim remains unproven/i);
  assert.match(evaluation, /release_ready: false/);
  assert.match(evaluation, /pairwise-distinct release markers/);
  assert.match(evaluation, /offline verification rejects only intra-bundle marker collisions/);
  assert.match(claims, /pairwise-distinct markers that do not collide/);
  assert.doesNotMatch(evaluation, /cannot assemble a fresh v3 transaction/);
  assert.match(protection, /does not authorize a live K0/i);
  assert.match(protection, /48-hour kill gate has not started/i);
  assert.doesNotMatch(protection, /\brelease_ready\s*:\s*true\b/);
  assert.doesNotMatch(readme, /\brelease_ready\s*:\s*true\b/);
  assert.doesNotMatch(master, /\brelease_ready\s*:\s*true\b/);

  assert.match(readme, /37\/37 deterministic mutation matrix/);
  assert.match(evaluation, /37\/37 deterministic/);
  const receipts = await readFile(resolve(root, "docs/RECEIPTS.md"), "utf8");
  const threat = await readFile(resolve(root, "docs/THREAT_MODEL.md"), "utf8");
  const plan = await readFile(resolve(root, "docs/DEVELOPMENT_PLAN.md"), "utf8");
  const quickstart = await readFile(resolve(root, "docs/QUICKSTART.md"), "utf8");
  const runbook = await readFile(resolve(root, "docs/REVIEWER_RUNBOOK.md"), "utf8");
  assert.match(receipts, /37\/37 named/);
  assert.match(threat, /37\/37/);
  assert.match(plan, /37\/37 deterministic mutations fail/);
  assert.doesNotMatch(readme, /36\/36/);
  assert.doesNotMatch(evaluation, /36\/36/);
  assert.doesNotMatch(receipts, /36\/36/);
  assert.doesNotMatch(threat, /36\/36/);
  assert.doesNotMatch(plan, /36\/36/);
  assert.match(quickstart, /KEYLESS_ALLOW_LIVE=1 npm run run:eval/);
  assert.match(quickstart, /KEYLESS_ALLOW_LIVE=1/);
  assert.match(runbook, /KEYLESS_ALLOW_LIVE=1 npm run proofv2 -- issue/);
  assert.match(runbook, /KEYLESS_ALLOW_LIVE=1 npm run proofv2 -- verify/);
});
