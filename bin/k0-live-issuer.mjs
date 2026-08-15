#!/usr/bin/env node

import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { GoogleAuth } from "google-auth-library";

import { canonicalJson, decodeUtf8 } from "../src/evidence-artifact.mjs";
import { readBoundedFile } from "../src/k0-bundle-files.mjs";
import { verifyK0Bundle } from "../src/k0-bundle.mjs";
import { createKmsSigningRequest } from "../src/k0-kms.mjs";
import { issueK0Live } from "../src/k0-live-issuer.mjs";
import { verifyK0Receipt } from "../src/k0-receipt.mjs";
import { rejectDuplicateJsonKeys } from "../src/observation-time.mjs";

const MAX_PLAN = 32 * 1024;
const MAX_OUTPUT = 2_000_000;
const OUTPUT_FIELDS = new Set([
  "version", "domain", "manifest_bytes_base64", "artifacts", "receipt_bytes_base64", "kms_request",
]);
const ARTIFACT_FIELDS = new Set(["id", "bytes_base64"]);
const KMS_REQUEST_FIELDS = new Set(["name", "digest"]);
const KMS_DIGEST_FIELDS = new Set(["sha256"]);

function exactObject(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === fields.size
    && Object.keys(value).every((field) => fields.has(field));
}

function requireOutputBasename(value) {
  if (typeof value !== "string" || value.length < 6 || value.length > 128
      || !/^[A-Za-z0-9][A-Za-z0-9._-]*\.json$/.test(value)) {
    throw new Error("K0 issuer output basename is invalid");
  }
  return value;
}

function decodeBase64(value, limit) {
  if (typeof value !== "string" || !value.length || value.length > Math.ceil(limit / 3) * 4
      || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error("K0 issuer output encoding is invalid");
  }
  const bytes = Buffer.from(value, "base64");
  if (!bytes.length || bytes.length > limit || bytes.toString("base64") !== value) {
    throw new Error("K0 issuer output encoding is invalid");
  }
  return bytes;
}

function pendingOutputBytes(result) {
  const artifacts = [...result.bundle.artifacts]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([id, bytes]) => ({ id, bytes_base64: bytes.toString("base64") }));
  return Buffer.from(canonicalJson({
    version: 1,
    domain: "KEYLESS_K0_LIVE_PENDING_OUTPUT_V1",
    manifest_bytes_base64: result.bundle.manifestBytes.toString("base64"),
    artifacts,
    receipt_bytes_base64: result.receipt.receiptBytes.toString("base64"),
    kms_request: result.kmsRequest,
  }), "utf8");
}

async function verifyPendingOutput(bytes, expected) {
  if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > MAX_OUTPUT) {
    throw new Error("K0 issuer pending output is invalid");
  }
  let value;
  try {
    const text = decodeUtf8(bytes);
    rejectDuplicateJsonKeys(text);
    value = JSON.parse(text);
  } catch (error) {
    if (error?.message === "duplicate JSON key") throw new Error("K0 issuer pending output contains duplicate JSON keys");
    throw new Error("K0 issuer pending output is not JSON");
  }
  if (!bytes.equals(Buffer.from(canonicalJson(value), "utf8"))
      || !exactObject(value, OUTPUT_FIELDS)
      || value.version !== 1 || value.domain !== "KEYLESS_K0_LIVE_PENDING_OUTPUT_V1"
      || !Array.isArray(value.artifacts) || value.artifacts.length < 1 || value.artifacts.length > 100
      || value.artifacts.some((item) => !exactObject(item, ARTIFACT_FIELDS)
        || !/^E\d{3}$/.test(item.id))
      || value.artifacts.some(({ id }, index) => index > 0 && value.artifacts[index - 1].id >= id)) {
    throw new Error("K0 issuer pending output is invalid");
  }
  const manifestBytes = decodeBase64(value.manifest_bytes_base64, 1_000_000);
  const receiptBytes = decodeBase64(value.receipt_bytes_base64, 1_000_000);
  const artifacts = new Map(value.artifacts.map(({ id, bytes_base64: encoded }) => [
    id, decodeBase64(encoded, 512_000),
  ]));
  let manifest;
  try {
    const text = decodeUtf8(manifestBytes);
    rejectDuplicateJsonKeys(text);
    manifest = JSON.parse(text);
  } catch (error) {
    if (error?.message === "duplicate JSON key") throw new Error("K0 issuer output manifest contains duplicate JSON keys");
    throw new Error("K0 issuer output manifest is not JSON");
  }
  if (!manifestBytes.equals(Buffer.from(canonicalJson(manifest), "utf8"))) {
    throw new Error("K0 issuer output manifest is not canonical");
  }
  await verifyK0Bundle({ manifest, artifacts });
  await verifyK0Receipt({ receiptBytes, manifest, manifestBytes, artifacts });
  if (!exactObject(value.kms_request, KMS_REQUEST_FIELDS)
      || !exactObject(value.kms_request.digest, KMS_DIGEST_FIELDS)
      || typeof value.kms_request.name !== "string"
      || typeof value.kms_request.digest.sha256 !== "string"
      || "release_ready" in value.kms_request
      || "authorization" in value.kms_request
      || "status" in value.kms_request) {
    throw new Error("K0 issuer pending output is invalid");
  }
  const kmsRequestBytes = Buffer.from(canonicalJson(value.kms_request), "utf8");
  const rebuiltRequest = createKmsSigningRequest(receiptBytes, value.kms_request.name);
  if (!kmsRequestBytes.equals(Buffer.from(canonicalJson(rebuiltRequest), "utf8"))
      || !manifestBytes.equals(expected.bundle.manifestBytes)
      || !receiptBytes.equals(expected.receipt.receiptBytes)
      || !kmsRequestBytes.equals(expected.kmsRequestBytes)
      || artifacts.size !== expected.bundle.artifacts.size) {
    throw new Error("K0 issuer pending output does not match recollection");
  }
  for (const [id, artifactBytes] of expected.bundle.artifacts) {
    if (!artifacts.get(id)?.equals(artifactBytes)) {
      throw new Error("K0 issuer pending output does not match recollection");
    }
  }
  return true;
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function internalOutputBarrier(stage, basename) {
  const barrier = globalThis.__KEYLESS_K0_INTERNAL_OUTPUT_BARRIER__;
  if (barrier !== undefined) {
    if (typeof barrier !== "function") throw new Error("K0 issuer output barrier is invalid");
    await barrier(stage, basename);
  }
}

async function reserveOutput(basename) {
  if (!Number.isInteger(constants.O_NOFOLLOW)) throw new Error("K0 issuer no-follow output is unavailable");
  const flags = constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW;
  const handle = await open(basename, flags, 0o600);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size !== 0 || (stat.mode & 0o777) !== 0o600 || stat.nlink !== 1) {
      throw new Error("K0 issuer output file is invalid");
    }
    return { handle, stat };
  } catch {
    try { await handle.close(); } catch { /* failure remains static */ }
    throw new Error("K0 issuer output file is invalid");
  }
}

async function writeRange(handle, bytes, start, end) {
  let offset = start;
  while (offset < end) {
    const { bytesWritten } = await handle.write(bytes, offset, end - offset, offset);
    if (!Number.isInteger(bytesWritten) || bytesWritten < 1) throw new Error("K0 issuer output write failed");
    offset += bytesWritten;
  }
}

async function readHandle(handle, length) {
  if (!Number.isInteger(length) || length < 1 || length > MAX_OUTPUT) {
    throw new Error("K0 issuer output file is invalid");
  }
  const bytes = Buffer.alloc(length);
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
    if (!Number.isInteger(bytesRead) || bytesRead < 1) throw new Error("K0 issuer output read failed");
    offset += bytesRead;
  }
  const trailing = Buffer.alloc(1);
  const { bytesRead } = await handle.read(trailing, 0, 1, length);
  if (bytesRead !== 0) throw new Error("K0 issuer output file has trailing bytes");
  return bytes;
}

async function invalidateReservedOutput(handle) {
  const makePrivate = async () => {
    try { await handle.chmod(0o600); } catch { /* retried after invalidation */ }
  };
  await makePrivate();
  try {
    await handle.truncate(0);
    await handle.sync();
    await makePrivate();
    return;
  } catch {
    // Poison byte zero before any optional shrink so stale envelope bytes cannot remain verifier-valid.
  }
  try {
    const marker = Buffer.from([0xff]);
    const { bytesWritten } = await handle.write(marker, 0, 1, 0);
    if (bytesWritten !== 1) throw new Error("K0 issuer invalidation write failed");
    await handle.sync();
    try { await handle.truncate(1); } catch { /* the durable invalid first byte is sufficient */ }
    try { await handle.sync(); } catch { /* best-effort durability after failure */ }
  } catch {
    try {
      await handle.truncate(0);
      await handle.sync();
    } catch {
      // If every independent held-handle mutation fails, no stdlib path operation can safely invalidate it.
    }
  }
  await makePrivate();
}

async function writeReservedOutput(result, basename, reservation, transaction) {
  const bytes = pendingOutputBytes(result);
  await verifyPendingOutput(bytes, result);
  const midpoint = Math.max(1, Math.floor(bytes.length / 2));
  await writeRange(reservation.handle, bytes, 0, midpoint);
  await internalOutputBarrier("after-partial-write", basename);
  await writeRange(reservation.handle, bytes, midpoint, bytes.length);
  await internalOutputBarrier("after-write", basename);
  await internalOutputBarrier("before-sync", basename);
  await reservation.handle.sync();
  await internalOutputBarrier("final-barrier", basename);
  const [pathStat, handleStat] = await Promise.all([lstat(basename), reservation.handle.stat()]);
  if (!pathStat.isFile() || pathStat.isSymbolicLink() || !handleStat.isFile()
      || !sameInode(pathStat, reservation.stat) || !sameInode(handleStat, reservation.stat)
      || (pathStat.mode & 0o777) !== 0o600 || (handleStat.mode & 0o777) !== 0o600
      || pathStat.nlink !== 1 || handleStat.nlink !== 1
      || pathStat.size !== bytes.length || handleStat.size !== bytes.length) {
    throw new Error("K0 issuer output file changed");
  }
  const captured = await readHandle(reservation.handle, bytes.length);
  if (!captured.equals(bytes)) throw new Error("K0 issuer output changed after writing");
  await verifyPendingOutput(captured, result);
  transaction.committed = true;
}

async function main(argv) {
  if (argv.length !== 2) throw new Error("invalid command");
  const outputBasename = requireOutputBasename(argv[1]);
  const planBytes = await readBoundedFile(resolve(argv[0]), MAX_PLAN);
  const reservation = await reserveOutput(outputBasename);
  let closed = false;
  const closeOutput = async () => {
    if (closed) return;
    closed = true;
    await reservation.handle.close();
  };
  const transaction = { committed: false };
  let result;
  try {
    await internalOutputBarrier("after-open", outputBasename);
    result = await issueK0Live(planBytes, {
      installationToken: process.env.KEYLESS_GITHUB_TOKEN,
      googleAuth: new GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform.read-only"] }),
    });
    await writeReservedOutput(result, outputBasename, reservation, transaction);
  } catch (error) {
    if (!transaction.committed) await invalidateReservedOutput(reservation.handle);
    throw error;
  } finally {
    try { await closeOutput(); } catch { /* close cannot change a committed result or restore invalid residue */ }
  }
  if (transaction.committed) {
    try {
      process.stdout.write(`K0_VERIFIED_RECEIPT_PENDING manifest_sha256=${result.manifest_sha256} receipt_sha256=${result.receipt_sha256}\n`);
    } catch {
      // The committed verifier-valid file is authoritative; stdout is best-effort only.
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(() => {
    process.stderr.write("K0 live issuer command failed\n");
    process.exitCode = 1;
  });
}
