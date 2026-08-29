import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createConsoleServer, renderConsoleHtml } from "../console/server.mjs";
import { loadConsoleStatus } from "../console/status.mjs";
import { canonicalJson } from "../src/evidence-artifact.mjs";
import { assembleK0Bundle } from "../src/k0-bundle.mjs";
import { createKmsSigningRequest } from "../src/k0-kms.mjs";
import { createK0Receipt } from "../src/k0-receipt.mjs";
import { validK0BundleInput } from "./fixtures/k0-bundle.mjs";
import { createTestKmsSigner } from "./support/k0-kms-signer.mjs";

const KEY_VERSION = "projects/example-project/locations/global/keyRings/keyless/cryptoKeys/k0-receipt/cryptoKeyVersions/1";

async function writeBundle(root, name, input = validK0BundleInput()) {
  const bundle = await assembleK0Bundle(input);
  const directory = join(root, name);
  await mkdir(join(directory, "artifacts"), { recursive: true });
  await writeFile(join(directory, "manifest.json"), bundle.manifestBytes);
  for (const [id, bytes] of bundle.artifacts) {
    await writeFile(join(directory, "artifacts", `${id}.json`), bytes);
  }
  return { bundle, directory };
}

async function writeSignedReceipt(root, bundle, name = "signed") {
  const { receiptBytes } = await createK0Receipt(bundle);
  const signer = createTestKmsSigner(KEY_VERSION);
  const sidecarBytes = signer.sidecar(receiptBytes, createKmsSigningRequest(receiptBytes, KEY_VERSION));
  const receiptPath = join(root, `${name}-receipt.json`);
  const signaturePath = join(root, `${name}-sidecar.json`);
  await writeFile(receiptPath, receiptBytes);
  await writeFile(signaturePath, sidecarBytes);
  return { receiptBytes, signer, sidecarBytes, receiptPath, signaturePath };
}

function assertFailed(status, hidden = "") {
  assert.equal(status.status, "NO_GO_VERIFICATION_FAILED");
  assert.equal(status.release_ready, false);
  assert.equal(status.cutover_verified, false);
  assert.equal(status.signature_verified, false);
  assert.deepEqual(status.metrics, []);
  if (hidden) assert.doesNotMatch(JSON.stringify(status), new RegExp(hidden));
}

test("exact external bundle reconstructs only a recollection-required pending receipt", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "keyless-console-k0-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const { directory } = await writeBundle(root, "bundle");
  const status = await loadConsoleStatus({ bundlePath: directory });
  assert.equal(status.status, "K0_VERIFIED_RECEIPT_PENDING");
  assert.equal(status.authorization, "RECOLLECTION_REQUIRED");
  assert.equal(status.release_ready, false);
  assert.equal(status.cutover_verified, false);
  assert.equal(status.signature_verified, false);
  assert.match(status.checkpoint_sha256, /^[a-f0-9]{64}$/);
  assert.equal(status.gates.find(({ label }) => label === "External v3 bundle").state, "passed");
  assert.deepEqual(status.metrics.find(({ label }) => label === "legacy claims in bundle"), {
    value: "2/2", label: "legacy claims in bundle",
  });
  assert.deepEqual(status.gates.find(({ label }) => label === "Legacy baseline"), {
    label: "Legacy baseline", state: "passed", detail: "keyless-demo-legacy-1",
  });
  assert.equal(status.gates.find(({ label }) => label === "Authenticated live pending issuance").state, "missing");
  assert.match(status.summary, /local read-only pending issuer exists and is tested/);
  assert.match(renderConsoleHtml(status), /Bundle verified · recollection required/);
  assert.doesNotThrow(() => createConsoleServer(status));
});

test("valid pinned test signature passes its gate but cannot promote cutover or release", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "keyless-console-signed-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const { bundle, directory } = await writeBundle(root, "bundle");
  const signed = await writeSignedReceipt(root, bundle);
  const mutableTrust = { ...signed.signer.trustAnchor };
  const pending = loadConsoleStatus({
    bundlePath: directory,
    receiptPath: signed.receiptPath,
    signaturePath: signed.signaturePath,
    trustAnchor: mutableTrust,
  });
  mutableTrust.algorithm = "WRONG";
  mutableTrust.key_version = "wrong";
  const status = await pending;
  assert.equal(status.status, "K0_VERIFIED_RECEIPT_PENDING");
  assert.equal(status.authorization, "RECOLLECTION_REQUIRED");
  assert.equal(status.signature_verified, true);
  assert.equal(status.cutover_verified, false);
  assert.equal(status.release_ready, false);
  assert.equal(status.gates.find(({ label }) => label === "Pinned KMS signature").state, "passed");
  assert.match(status.summary, /local read-only pending issuer exists and is tested/);
  assert.match(renderConsoleHtml(status), /Signature verified · recollection required/);
});

test("configured invalid bundle files fail without checkpoint fallback or evidence echo", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "keyless-console-bundle-chaos-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const cases = [
    ["missing-manifest", async (directory) => unlink(join(directory, "manifest.json"))],
    ["missing-artifact", async (directory) => unlink(join(directory, "artifacts", "E001.json"))],
    ["extra", async (directory) => writeFile(join(directory, "artifacts", "extra.json"), "{}")],
    ["symlink-manifest", async (directory) => {
      await unlink(join(directory, "manifest.json"));
      await symlink(join(directory, "artifacts", "E001.json"), join(directory, "manifest.json"));
    }],
    ["symlink-artifact", async (directory) => {
      await unlink(join(directory, "artifacts", "E001.json"));
      await symlink(join(directory, "manifest.json"), join(directory, "artifacts", "E001.json"));
    }],
    ["noncanonical-manifest", async (directory) => {
      const path = join(directory, "manifest.json");
      await writeFile(path, Buffer.concat([Buffer.from(" "), await readFile(path)]));
    }],
    ["noncanonical-artifact", async (directory) => {
      const path = join(directory, "artifacts", "E001.json");
      await writeFile(path, Buffer.concat([Buffer.from(" "), await readFile(path)]));
    }],
    ["truncated-manifest", async (directory) => {
      const path = join(directory, "manifest.json");
      const bytes = await readFile(path);
      await writeFile(path, bytes.subarray(0, bytes.length - 1));
    }],
    ["truncated-artifact", async (directory) => {
      const path = join(directory, "artifacts", "E001.json");
      const bytes = await readFile(path);
      await writeFile(path, bytes.subarray(0, bytes.length - 1));
    }],
    ["oversize-manifest", async (directory) => writeFile(join(directory, "manifest.json"), Buffer.alloc(1_000_001, 0x20))],
    ["oversize-artifact", async (directory) => writeFile(join(directory, "artifacts", "E001.json"), Buffer.alloc(512_001, 0x20))],
    ["credential-manifest", async (directory) => writeFile(
      join(directory, "manifest.json"), canonicalJson({ private_key: "never-display-this-marker" }),
    )],
    ["credential-artifact", async (directory) => writeFile(
      join(directory, "artifacts", "E001.json"), canonicalJson({ private_key: "never-display-this-marker" }),
    )],
  ];
  for (const [name, mutate] of cases) {
    const { directory } = await writeBundle(root, `bundle-${name}`);
    await mutate(directory);
    const status = await loadConsoleStatus({
      checkpointPath: "this-must-not-be-read.json",
      bundlePath: directory,
    });
    assertFailed(status, "never-display-this-marker");
    assert.doesNotMatch(renderConsoleHtml(status), /never-display-this-marker/);
    assert.match(renderConsoleHtml(status), /Verification failed/);
  }
});

test("any partial optional receipt, signature, or trust configuration fails closed", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "keyless-console-partial-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const { bundle, directory } = await writeBundle(root, "bundle");
  const signed = await writeSignedReceipt(root, bundle);
  const values = {
    receiptPath: signed.receiptPath,
    signaturePath: signed.signaturePath,
    trustAnchor: signed.signer.trustAnchor,
  };
  for (const keys of [
    ["receiptPath"], ["signaturePath"], ["trustAnchor"],
    ["receiptPath", "signaturePath"], ["receiptPath", "trustAnchor"], ["signaturePath", "trustAnchor"],
  ]) {
    assertFailed(await loadConsoleStatus({
      bundlePath: directory,
      ...Object.fromEntries(keys.map((key) => [key, values[key]])),
    }));
  }
  assertFailed(await loadConsoleStatus({ ...values }));
});

test("receipt and sidecar byte attacks take precedence over a valid bundle", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "keyless-console-upper-chaos-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const { bundle, directory } = await writeBundle(root, "bundle");
  const signed = await writeSignedReceipt(root, bundle);
  const config = {
    bundlePath: directory,
    receiptPath: signed.receiptPath,
    signaturePath: signed.signaturePath,
    trustAnchor: signed.signer.trustAnchor,
  };
  const different = validK0BundleInput();
  different.manifest.limitations = ["A different synthetic limitation."];
  const differentReceipt = await createK0Receipt(await assembleK0Bundle(different));
  const receiptCases = [
    ["noncanonical", Buffer.concat([signed.receiptBytes, Buffer.from(" ")])],
    ["truncated", signed.receiptBytes.subarray(0, signed.receiptBytes.length - 1)],
    ["oversize", Buffer.alloc(1_000_001, 0x20)],
    ["credential", Buffer.from('{"private_key":"never-display-this-marker"}\n')],
    ["bundle mismatch", differentReceipt.receiptBytes],
    ["extra field", (() => {
      const value = JSON.parse(signed.receiptBytes);
      value.extra = true;
      return Buffer.from(canonicalJson(value));
    })()],
  ];
  for (const [name, bytes] of receiptCases) {
    await writeFile(signed.receiptPath, bytes);
    assertFailed(await loadConsoleStatus(config), name === "credential" ? "never-display-this-marker" : "");
  }
  await writeFile(signed.receiptPath, signed.receiptBytes);
  await unlink(signed.receiptPath);
  assertFailed(await loadConsoleStatus(config));
  await symlink(signed.signaturePath, signed.receiptPath);
  assertFailed(await loadConsoleStatus(config));
  await unlink(signed.receiptPath);
  await writeFile(signed.receiptPath, signed.receiptBytes);

  const parsedSidecar = JSON.parse(signed.sidecarBytes);
  const changedSidecar = (mutate) => {
    const value = structuredClone(parsedSidecar);
    mutate(value);
    return Buffer.from(canonicalJson(value));
  };
  const signature = Buffer.from(parsedSidecar.signature, "base64");
  const changedSignature = Buffer.from(signature);
  changedSignature[0] ^= 1;
  const sidecarCases = [
    ["noncanonical", Buffer.concat([signed.sidecarBytes, Buffer.from(" ")])],
    ["truncated", signed.sidecarBytes.subarray(0, signed.sidecarBytes.length - 1)],
    ["oversize", Buffer.alloc(16_385, 0x20)],
    ["credential", Buffer.from('{"private_key":"never-display-this-marker"}\n')],
    ["key version", changedSidecar((value) => { value.name = value.name.replace(/\/1$/, "/2"); })],
    ["algorithm", changedSidecar((value) => { value.algorithm = "WRONG"; })],
    ["digest", changedSidecar((value) => { value.digest_sha256 = Buffer.alloc(32).toString("base64"); })],
    ["signature", changedSidecar((value) => { value.signature = changedSignature.toString("base64"); })],
    ["extra field", changedSidecar((value) => { value.extra = true; })],
  ];
  for (const [name, bytes] of sidecarCases) {
    await writeFile(signed.signaturePath, bytes);
    assertFailed(await loadConsoleStatus(config), name === "credential" ? "never-display-this-marker" : "");
  }
  await unlink(signed.signaturePath);
  assertFailed(await loadConsoleStatus(config));
  await symlink(signed.receiptPath, signed.signaturePath);
  assertFailed(await loadConsoleStatus(config));
});

test("wrong public key and a second valid local key substitution fail against pinned trust", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "keyless-console-key-chaos-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const { bundle, directory } = await writeBundle(root, "bundle");
  const signed = await writeSignedReceipt(root, bundle);
  const second = createTestKmsSigner(KEY_VERSION);
  const base = {
    bundlePath: directory,
    receiptPath: signed.receiptPath,
    signaturePath: signed.signaturePath,
  };
  assertFailed(await loadConsoleStatus({
    ...base,
    trustAnchor: { ...signed.signer.trustAnchor, public_key: second.trustAnchor.public_key },
  }));
  assertFailed(await loadConsoleStatus({
    ...base,
    trustAnchor: { ...signed.signer.trustAnchor, key_version: signed.signer.trustAnchor.key_version.replace(/\/1$/, "/2") },
  }));
  assertFailed(await loadConsoleStatus({
    ...base,
    trustAnchor: { ...signed.signer.trustAnchor, algorithm: "WRONG" },
  }));

  await writeFile(signed.signaturePath, second.sidecar(
    signed.receiptBytes,
    createKmsSigningRequest(signed.receiptBytes, KEY_VERSION),
  ));
  assertFailed(await loadConsoleStatus({ ...base, trustAnchor: signed.signer.trustAnchor }));
});

test("post-capture disk tampering cannot promote an already pending status and is rejected on reload", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "keyless-console-capture-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const { bundle, directory } = await writeBundle(root, "bundle");
  const signed = await writeSignedReceipt(root, bundle);
  const config = {
    bundlePath: directory,
    receiptPath: signed.receiptPath,
    signaturePath: signed.signaturePath,
    trustAnchor: signed.signer.trustAnchor,
  };
  const captured = await loadConsoleStatus(config);
  const artifactPath = join(directory, "artifacts", "E001.json");
  const bytes = await readFile(artifactPath);
  await writeFile(artifactPath, bytes.subarray(0, bytes.length - 1));
  assert.equal(captured.release_ready, false);
  assert.equal(captured.cutover_verified, false);
  assert.equal(captured.status, "K0_VERIFIED_RECEIPT_PENDING");
  assertFailed(await loadConsoleStatus(config));
});
