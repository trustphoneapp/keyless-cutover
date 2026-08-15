import assert from "node:assert/strict";
import { mkdtemp, writeFile, link, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { readBoundedFile } from "../src/k0-bundle-files.mjs";

test("bounded file reader refuses hardlinks and size races", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "keyless-bounded-"));
  const path = join(directory, "artifact.json");
  const alias = join(directory, "alias.json");
  await writeFile(path, "{\"ok\":true}\n", { flag: "wx", mode: 0o600 });
  t.after(async () => {
    await unlink(path).catch(() => {});
    await unlink(alias).catch(() => {});
  });

  assert.deepEqual(await readBoundedFile(path, 64), Buffer.from("{\"ok\":true}\n"));

  await link(path, alias);
  await assert.rejects(readBoundedFile(path, 64), /bounded file is invalid/);
  await assert.rejects(readBoundedFile(alias, 64), /bounded file is invalid/);
  await unlink(alias);

  await assert.rejects(readBoundedFile(path, 5), /bounded file is invalid/);
});
