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
  assert.match(evaluation, /pairwise-distinct unused release markers/);
  assert.match(claims, /pairwise distinct and unused/);
  assert.match(protection, /does not authorize a live K0/i);
  assert.match(protection, /48-hour kill gate has not started/i);
  assert.doesNotMatch(protection, /\brelease_ready\s*:\s*true\b/);
  assert.doesNotMatch(readme, /\brelease_ready\s*:\s*true\b/);
  assert.doesNotMatch(master, /\brelease_ready\s*:\s*true\b/);
});
