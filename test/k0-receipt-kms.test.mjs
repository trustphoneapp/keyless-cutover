import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../src/evidence-artifact.mjs";
import { assembleK0Bundle } from "../src/k0-bundle.mjs";
import {
  createKmsSigningRequest,
  verifyKmsSignature,
} from "../src/k0-kms.mjs";
import { createK0Receipt, parseK0ReceiptBytes, verifyK0Receipt } from "../src/k0-receipt.mjs";
import { evidenceByKind, validK0BundleInput } from "./fixtures/k0-bundle.mjs";
import { createTestKmsSigner } from "./support/k0-kms-signer.mjs";

const KEY_VERSION = "projects/example-project/locations/global/keyRings/keyless/cryptoKeys/k0-receipt/cryptoKeyVersions/1";

function changedReceipt(receipt, mutate) {
  const changed = structuredClone(receipt);
  mutate(changed);
  return Buffer.from(canonicalJson(changed));
}

function changedSidecar(sidecarBytes, mutate) {
  const changed = JSON.parse(sidecarBytes);
  mutate(changed);
  return Buffer.from(canonicalJson(changed));
}

test("pending K0 receipt reconstructs byte-identically and verifies with a pinned KMS public key", async () => {
  const bundle = await assembleK0Bundle(validK0BundleInput());
  const first = await createK0Receipt(bundle);
  const second = await createK0Receipt(bundle);
  const reordered = await createK0Receipt({
    ...bundle,
    artifacts: new Map([...bundle.artifacts].reverse()),
  });
  assert.deepEqual(first.receiptBytes, second.receiptBytes);
  assert.deepEqual(first.receiptBytes, reordered.receiptBytes);
  assert.equal(first.receipt.receipt_id, first.receipt.manifest_sha256);
  assert.equal(first.receipt.manifest_sha256, createHash("sha256").update(bundle.manifestBytes).digest("hex"));
  assert.equal(first.receipt.issued_at, bundle.manifest.assembled_at);
  assert.equal(first.receipt.domain, "KEYLESS_K0_PENDING_RECEIPT_V1");
  assert.equal(first.receipt.authorization, "RECOLLECTION_REQUIRED");
  assert.equal(first.receipt.status, "K0_VERIFIED_RECEIPT_PENDING");
  assert.equal(first.receipt.release_ready, false);
  assert.deepEqual(first.receipt.verified_results.legacy_baseline, bundle.manifest.legacy_baseline);
  assert.equal(await verifyK0Receipt({ receiptBytes: first.receiptBytes, ...bundle }), true);

  const signer = createTestKmsSigner(KEY_VERSION);
  const request = createKmsSigningRequest(first.receiptBytes, KEY_VERSION);
  const sidecar = signer.sidecar(first.receiptBytes, request);
  assert.deepEqual(request, {
    name: KEY_VERSION,
    digest: { sha256: JSON.parse(sidecar).digest_sha256 },
  });
  assert.equal(JSON.parse(sidecar).algorithm, "RSA_SIGN_PKCS1_2048_SHA256");
  assert.equal(verifyKmsSignature(first.receiptBytes, sidecar, signer.trustAnchor), true);
});

test("receipt construction snapshots the verified bundle before yielding", async () => {
  const bundle = await assembleK0Bundle(validK0BundleInput());
  const mutable = {
    manifest: structuredClone(bundle.manifest),
    manifestBytes: Buffer.from(bundle.manifestBytes),
    artifacts: new Map([...bundle.artifacts].map(([id, bytes]) => [id, Buffer.from(bytes)])),
  };
  const pending = createK0Receipt(mutable);
  mutable.manifestBytes[0] ^= 1;
  mutable.manifest.scope.project_id = "wrong-project";
  mutable.artifacts.get(mutable.manifest.evidence[0].id)[0] ^= 1;
  const created = await pending;
  assert.equal(created.receipt.scope.project_id, bundle.manifest.scope.project_id);
  assert.equal(await verifyK0Receipt({ receiptBytes: created.receiptBytes, ...bundle }), true);

  const verifyMutable = {
    manifest: structuredClone(bundle.manifest),
    manifestBytes: Buffer.from(bundle.manifestBytes),
    artifacts: new Map([...bundle.artifacts].map(([id, bytes]) => [id, Buffer.from(bytes)])),
  };
  const verifying = verifyK0Receipt({ receiptBytes: created.receiptBytes, ...verifyMutable });
  verifyMutable.manifestBytes[0] ^= 1;
  verifyMutable.manifest.scope.project_id = "wrong-project";
  verifyMutable.artifacts.get(verifyMutable.manifest.evidence[0].id)[0] ^= 1;
  assert.equal(await verifying, true);
});

test("receipt rejects absent, malformed, noncanonical, changed, or mismatched manifest bytes", async () => {
  const bundle = await assembleK0Bundle(validK0BundleInput());
  const { receiptBytes } = await createK0Receipt(bundle);
  const parsed = JSON.parse(bundle.manifestBytes);
  const reordered = Buffer.from(`${JSON.stringify(Object.fromEntries(Object.entries(parsed).reverse()))}\n`);
  const changed = Buffer.from(bundle.manifestBytes.toString("utf8").replace('"version":3', '"version":2'));
  const surrogate = Buffer.from(bundle.manifestBytes.toString("utf8")
    .replace('"example-project"', '"\\ud800"'));
  const cases = [
    ["absent", undefined, bundle.manifest],
    ["oversize", Buffer.alloc(1_000_001, 0x20), bundle.manifest],
    ["malformed", Buffer.from("{"), bundle.manifest],
    ["invalid UTF-8", Buffer.from([0xff]), bundle.manifest],
    ["overlong UTF-8", Buffer.from([0xc0, 0xaf]), bundle.manifest],
    ["surrogate UTF-8", Buffer.from([0xed, 0xa0, 0x80]), bundle.manifest],
    ["lone JSON surrogate", surrogate, bundle.manifest],
    ["prefixed whitespace", Buffer.concat([Buffer.from(" "), bundle.manifestBytes]), bundle.manifest],
    ["key reordered", reordered, bundle.manifest],
    ["truncated", bundle.manifestBytes.subarray(0, bundle.manifestBytes.length - 1), bundle.manifest],
    ["one byte changed", changed, bundle.manifest],
    ["object mismatch", bundle.manifestBytes, { ...bundle.manifest, scope: { ...bundle.manifest.scope, region: "us-east1" } }],
  ];
  for (const [label, manifestBytes, manifest] of cases) {
    await assert.rejects(createK0Receipt({ manifestBytes, manifest, artifacts: bundle.artifacts }), undefined, label);
    await assert.rejects(verifyK0Receipt({ receiptBytes, manifestBytes, manifest, artifacts: bundle.artifacts }), undefined, label);
  }
  for (const bytes of [Buffer.from([0xff]), Buffer.from([0xc0, 0xaf]), Buffer.from([0xed, 0xa0, 0x80])]) {
    assert.throws(() => parseK0ReceiptBytes(bytes), /not JSON/);
    await assert.rejects(() => verifyK0Receipt({ receiptBytes: bytes, ...bundle }), /not JSON/);
  }
  const surrogateReceipt = Buffer.from(receiptBytes.toString("utf8")
    .replace('"RECOLLECTION_REQUIRED"', '"\\ud800"'));
  assert.throws(() => parseK0ReceiptBytes(surrogateReceipt), /Unicode surrogate/);
  await assert.rejects(() => verifyK0Receipt({ receiptBytes: surrogateReceipt, ...bundle }), /Unicode surrogate/);
});

test("36 deterministic bundle, receipt, signature, and trust mutations all fail closed", async () => {
  const input = validK0BundleInput();
  const bundle = await assembleK0Bundle(input);
  const { receipt, receiptBytes } = await createK0Receipt(bundle);
  const signer = createTestKmsSigner(KEY_VERSION);
  const request = createKmsSigningRequest(receiptBytes, KEY_VERSION);
  const sidecar = signer.sidecar(receiptBytes, request);
  const secondSigner = createTestKmsSigner(KEY_VERSION);
  const signatureBytes = Buffer.from(JSON.parse(sidecar).signature, "base64");

  const mutations = [
    ["manifest scope drift", async () => {
      const changed = validK0BundleInput();
      changed.manifest.scope.project_id = "wrong-project";
      await assembleK0Bundle(changed);
    }],
    ["manifest evidence order", () => {
      const manifest = structuredClone(bundle.manifest);
      manifest.evidence.reverse();
      return verifyK0Receipt({ receiptBytes, manifestBytes: bundle.manifestBytes, manifest, artifacts: bundle.artifacts });
    }],
    ["semantic artifact drift with reconstructed digest", async () => {
      const changed = validK0BundleInput();
      evidenceByKind(changed, "GCP_WIF_PROVIDER").data.project_id = "wrong-project";
      await assembleK0Bundle(changed);
    }],
    ["missing artifact", async () => {
      const changed = validK0BundleInput();
      changed.evidence.pop();
      await assembleK0Bundle(changed);
    }],
    ["extra unreferenced artifact", async () => {
      const changed = validK0BundleInput();
      changed.evidence.push({ ...structuredClone(changed.evidence.at(-1)), id: "E099" });
      await assembleK0Bundle(changed);
    }],
    ["duplicate artifact", async () => {
      const changed = validK0BundleInput();
      changed.evidence.push(structuredClone(changed.evidence.at(-1)));
      await assembleK0Bundle(changed);
    }],
    ["wrong manifest digest", () => verifyK0Receipt({
      receiptBytes: changedReceipt(receipt, (value) => { value.manifest_sha256 = "0".repeat(64); }), ...bundle,
    })],
    ["wrong receipt id", () => verifyK0Receipt({
      receiptBytes: changedReceipt(receipt, (value) => { value.receipt_id = "0".repeat(64); }), ...bundle,
    })],
    ["wrong evidence order", () => verifyK0Receipt({
      receiptBytes: changedReceipt(receipt, (value) => { value.evidence.reverse(); }), ...bundle,
    })],
    ["wrong evidence digest", () => verifyK0Receipt({
      receiptBytes: changedReceipt(receipt, (value) => { value.evidence[0].sha256 = "0".repeat(64); }), ...bundle,
    })],
    ["wrong evidence kind", () => verifyK0Receipt({
      receiptBytes: changedReceipt(receipt, (value) => { value.evidence[0].kind = "WRONG"; }), ...bundle,
    })],
    ["wrong scope", () => verifyK0Receipt({
      receiptBytes: changedReceipt(receipt, (value) => { value.scope.project_id = "wrong-project"; }), ...bundle,
    })],
    ["wrong result", () => verifyK0Receipt({
      receiptBytes: changedReceipt(receipt, (value) => { value.verified_results.post_disable.outcome = "WRONG"; }), ...bundle,
    })],
    ["wrong limitations", () => verifyK0Receipt({
      receiptBytes: changedReceipt(receipt, (value) => { value.limitations[0] = "wrong"; }), ...bundle,
    })],
    ["wrong status", () => verifyK0Receipt({
      receiptBytes: changedReceipt(receipt, (value) => { value.status = "WRONG"; }), ...bundle,
    })],
    ["release ready", () => verifyK0Receipt({
      receiptBytes: changedReceipt(receipt, (value) => { value.release_ready = true; }), ...bundle,
    })],
    ["authorization bypass", () => verifyK0Receipt({
      receiptBytes: changedReceipt(receipt, (value) => { value.authorization = "WRONG"; }), ...bundle,
    })],
    ["wrong issued time", () => verifyK0Receipt({
      receiptBytes: changedReceipt(receipt, (value) => { value.issued_at = "2026-08-13T12:20:01Z"; }), ...bundle,
    })],
    ["wrong domain", () => verifyK0Receipt({
      receiptBytes: changedReceipt(receipt, (value) => { value.domain = "WRONG"; }), ...bundle,
    })],
    ["extra receipt field", () => verifyK0Receipt({
      receiptBytes: changedReceipt(receipt, (value) => { value.extra = true; }), ...bundle,
    })],
    ["receipt whitespace", () => verifyK0Receipt({ receiptBytes: Buffer.concat([Buffer.from(" "), receiptBytes]), ...bundle })],
    ["receipt trailing newline", () => verifyK0Receipt({ receiptBytes: Buffer.concat([receiptBytes, Buffer.from("\n")]), ...bundle })],
    ["malformed receipt JSON", () => verifyK0Receipt({ receiptBytes: Buffer.from("{"), ...bundle })],
    ["truncated receipt", () => verifyK0Receipt({ receiptBytes: receiptBytes.subarray(0, receiptBytes.length - 1), ...bundle })],
    ["oversize receipt", () => verifyK0Receipt({ receiptBytes: Buffer.alloc(1_000_001, 0x20), ...bundle })],
    ["wrong KMS key version", () => verifyKmsSignature(receiptBytes, changedSidecar(sidecar, (value) => {
      value.name = value.name.replace(/\/1$/, "/2");
    }), signer.trustAnchor)],
    ["wrong KMS algorithm", () => verifyKmsSignature(receiptBytes, changedSidecar(sidecar, (value) => {
      value.algorithm = "WRONG";
    }), signer.trustAnchor)],
    ["wrong KMS digest", () => verifyKmsSignature(receiptBytes, changedSidecar(sidecar, (value) => {
      value.digest_sha256 = Buffer.alloc(32).toString("base64");
    }), signer.trustAnchor)],
    ["wrong KMS signature", () => verifyKmsSignature(receiptBytes, changedSidecar(sidecar, (value) => {
      const changed = Buffer.from(signatureBytes);
      changed[0] ^= 1;
      value.signature = changed.toString("base64");
    }), signer.trustAnchor)],
    ["extra sidecar field", () => verifyKmsSignature(receiptBytes, changedSidecar(sidecar, (value) => {
      value.extra = true;
    }), signer.trustAnchor)],
    ["noncanonical sidecar", () => verifyKmsSignature(receiptBytes, Buffer.concat([sidecar, Buffer.from(" ")]), signer.trustAnchor)],
    ["wrong public key", () => verifyKmsSignature(receiptBytes, sidecar, {
      ...signer.trustAnchor, public_key: secondSigner.trustAnchor.public_key,
    })],
    ["wrong trust algorithm", () => verifyKmsSignature(receiptBytes, sidecar, {
      ...signer.trustAnchor, algorithm: "WRONG",
    })],
    ["wrong trust key version", () => verifyKmsSignature(receiptBytes, sidecar, {
      ...signer.trustAnchor, key_version: KEY_VERSION.replace(/\/1$/, "/2"),
    })],
    ["valid second key substitution", () => {
      const changedBytes = changedReceipt(receipt, (value) => { value.limitations[0] = "substituted"; });
      const changedRequest = createKmsSigningRequest(changedBytes, KEY_VERSION);
      const changedSidecar = secondSigner.sidecar(changedBytes, changedRequest);
      return verifyKmsSignature(changedBytes, changedSidecar, signer.trustAnchor);
    }],
    ["invalid request key version", () => createKmsSigningRequest(receiptBytes, "cryptoKeyVersions/1")],
  ];
  assert.equal(mutations.length, 36);
  for (const [label, mutate] of mutations) await assert.rejects(async () => mutate(), undefined, label);
});

test("KMS helpers refuse AUTHORIZED or release_ready receipts and never promote", async () => {
  const bundle = await assembleK0Bundle(validK0BundleInput());
  const { receipt, receiptBytes } = await createK0Receipt(bundle);
  const signer = createTestKmsSigner(KEY_VERSION);
  const request = createKmsSigningRequest(receiptBytes, KEY_VERSION);
  const sidecar = signer.sidecar(receiptBytes, request);

  assert.equal(verifyKmsSignature(receiptBytes, sidecar, signer.trustAnchor), true);
  assert.equal(parseK0ReceiptBytes(receiptBytes).authorization, "RECOLLECTION_REQUIRED");
  assert.equal(parseK0ReceiptBytes(receiptBytes).release_ready, false);

  const authorized = changedReceipt(receipt, (value) => { value.authorization = "AUTHORIZED"; });
  const promoted = changedReceipt(receipt, (value) => { value.release_ready = true; });
  assert.throws(() => createKmsSigningRequest(authorized, KEY_VERSION));
  assert.throws(() => createKmsSigningRequest(promoted, KEY_VERSION));
  assert.throws(() => verifyKmsSignature(authorized, sidecar, signer.trustAnchor));
  assert.throws(() => verifyKmsSignature(promoted, sidecar, signer.trustAnchor));

  const authorizedSidecar = (() => {
    try {
      return signer.sidecar(authorized, {
        name: KEY_VERSION,
        digest: { sha256: createHash("sha256").update(authorized).digest("base64") },
      });
    } catch {
      return null;
    }
  })();
  if (authorizedSidecar) {
    assert.throws(() => verifyKmsSignature(authorized, authorizedSidecar, signer.trustAnchor));
  }

  assert.throws(() => parseK0ReceiptBytes(changedReceipt(receipt, (value) => {
    value.scope = { ...value.scope, authorization: "AUTHORIZED" };
  })), /invalid/);
  assert.throws(() => parseK0ReceiptBytes(changedReceipt(receipt, (value) => {
    delete value.scope.key_id;
  })), /invalid/);
});
