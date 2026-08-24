import assert from "node:assert/strict";
import { brotliCompressSync, deflateRawSync, deflateSync, gzipSync } from "node:zlib";
import { test } from "node:test";

import { assertCredentialFreeBytes, createCredentialScan } from "../src/credential-scan.mjs";

const privateKey = `-----BEGIN ${"PRIVATE"} KEY-----\nexample\n-----END PRIVATE KEY-----`;
const githubToken = `gh${"p"}_${"a".repeat(24)}`;
const fineGrainedGithubToken = `github_${"pat"}_${"a".repeat(24)}`;
const googleToken = `ya${"29"}.${"b".repeat(24)}`;
const googleApiKey = `AI${"za"}${"c".repeat(35)}`;

test("credential scan is deterministic and reports no matched material", () => {
  const scope = { project_id: "example-project", repository_id: "2" };
  const first = createCredentialScan(scope, new Map([
    ["E002", Buffer.from("clean-two")],
    ["E001", Buffer.from("clean-one")],
  ]));
  const second = createCredentialScan(structuredClone(scope), new Map([
    ["E001", Buffer.from("clean-one")],
    ["E002", Buffer.from("clean-two")],
  ]));
  assert.deepEqual(first, second);
  assert.deepEqual(Object.keys(first), ["outcome", "scanner", "scope_hash", "artifact_count"]);
  assert.equal(first.outcome, "CLEAN");
  assert.equal(first.scanner, "KEYLESS_CREDENTIAL_SCAN_V1");
  assert.equal(first.artifact_count, 2);
  assert.match(first.scope_hash, /^[a-f0-9]{64}$/);
  assert.notEqual(createCredentialScan(scope, new Map([
    ["E001", Buffer.from("changed")],
    ["E002", Buffer.from("clean-two")],
  ])).scope_hash, first.scope_hash);
  assert.notEqual(createCredentialScan(scope, new Map([
    ["E001", Buffer.from("clean-one")],
    ["E003", Buffer.from("clean-two")],
  ])).scope_hash, first.scope_hash);
});

test("credential scan rejects raw, escaped, URL-encoded, and bounded base64 variants without echo", () => {
  const variants = [
    privateKey,
    JSON.stringify({ private_key: "example" }),
    JSON.stringify({ value: privateKey }),
    encodeURIComponent(privateKey),
    `%ZZ:${encodeURIComponent(githubToken)}`,
    githubToken,
    fineGrainedGithubToken,
    googleToken,
    googleApiKey,
    `Authorization: Bearer ${"d".repeat(24)}`,
    Buffer.from(privateKey).toString("base64"),
    `prefix:${Buffer.from(githubToken).toString("base64")}:suffix`,
    Buffer.from(encodeURIComponent(googleToken)).toString("base64url"),
    `token ${Buffer.from(`${privateKey.split("\n")[0]}\n\u00ff\u00fe`).toString("base64").replace(/\+/g, "-").replace(/\//g, "_")}`,
  ];
  for (const value of variants) {
    assert.throws(
      () => assertCredentialFreeBytes(Buffer.from(value)),
      (error) => error.message === "credential-shaped material detected"
        && !error.message.includes("example") && !error.message.includes("Bearer"),
    );
  }
});

test("credential scan inspects decoded JSON strings directly and recursively", () => {
  const escaped = `{"value":"gh\\u0070_${"a".repeat(24)}"}`;
  const nested = JSON.stringify({ payload: escaped });
  const encoded = JSON.stringify({ payload: Buffer.from(githubToken).toString("base64") });
  const escapedKey = `{"gh\\u0070_${"a".repeat(24)}":"clean"}`;
  const encodedKey = JSON.stringify({
    nested: { [Buffer.from(githubToken).toString("base64")]: "clean" },
  });
  const encodedNestedKey = JSON.stringify({
    payload: Buffer.from(escapedKey).toString("base64"),
  });
  for (const value of [escaped, nested, encoded, escapedKey, encodedKey, encodedNestedKey]) {
    assert.throws(
      () => assertCredentialFreeBytes(Buffer.from(value)),
      (error) => error.message === "credential-shaped material detected" && !error.message.includes(githubToken),
    );
  }
});

test("credential scan rejects invalid input bounds and artifact maps", () => {
  assert.throws(() => assertCredentialFreeBytes(Buffer.alloc(0)), /input is invalid/);
  assert.throws(() => assertCredentialFreeBytes(Buffer.alloc(700 * 1024 + 1)), /input is invalid/);
  assert.throws(() => createCredentialScan({}, new Map()), /artifacts are invalid/);
  assert.throws(() => createCredentialScan({}, {}), /artifacts are invalid/);
});

test("credential scan recursively detects three encoded layers and rejects compressed payloads", () => {
  const encoded = (value, layers) => Array.from({ length: layers })
    .reduce((current) => Buffer.from(current).toString("base64"), value);
  assert.throws(() => assertCredentialFreeBytes(Buffer.from(encoded(githubToken, 3))), /credential-shaped/);
  assert.throws(() => assertCredentialFreeBytes(Buffer.from(
    encodeURIComponent(encodeURIComponent(privateKey)),
  )), /credential-shaped/);

  const compressed = [
    gzipSync(Buffer.from(githubToken)),
    deflateSync(Buffer.from("clean")),
    Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(16)]),
    Buffer.concat([Buffer.from([0x42, 0x5a, 0x68]), Buffer.alloc(16)]),
    Buffer.concat([Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]), Buffer.alloc(16)]),
  ];
  for (const bytes of compressed) {
    assert.throws(
      () => assertCredentialFreeBytes(Buffer.from(bytes.toString("base64"))),
      { message: "UNSUPPORTED_ENCODED_PAYLOAD" },
    );
  }
  const percentEncodedGzip = [...compressed[0]].map((byte) => `%${byte.toString(16).padStart(2, "0")}`).join("");
  assert.throws(
    () => assertCredentialFreeBytes(Buffer.from(percentEncodedGzip)),
    { message: "UNSUPPORTED_ENCODED_PAYLOAD" },
  );
  for (let window = 0; window <= 7; window += 1) {
    const cmf = (window << 4) | 8;
    const flg = Array.from({ length: 256 }, (_, value) => value)
      .find((value) => ((cmf << 8) + value) % 31 === 0);
    const payload = Buffer.concat([Buffer.from([cmf, flg]), Buffer.alloc(16)]).toString("base64");
    assert.throws(
      () => assertCredentialFreeBytes(Buffer.from(payload)),
      { message: "UNSUPPORTED_ENCODED_PAYLOAD" },
    );
  }

  assert.doesNotThrow(() => assertCredentialFreeBytes(Buffer.from(encoded("clean payload", 3))));
  assert.doesNotThrow(() => assertCredentialFreeBytes(Buffer.from(
    encodeURIComponent(encodeURIComponent("clean payload")),
  )));
  assert.doesNotThrow(() => assertCredentialFreeBytes(Buffer.from(
    Buffer.from("ordinary Unicode 🙂 text\tline\nend\r").toString("base64"),
  )));
  for (const bytes of [deflateRawSync(Buffer.from("clean")), brotliCompressSync(Buffer.from("clean"))]) {
    assert.doesNotThrow(() => assertCredentialFreeBytes(Buffer.from(bytes.toString("base64"))));
  }
});

test("credential scan fails closed on candidate and decoded-byte budget exhaustion", () => {
  const candidate = Buffer.from("clean-payload").toString("base64");
  const explosion = Array.from({ length: 2_049 }, () => candidate).join(".");
  assert.throws(() => assertCredentialFreeBytes(Buffer.from(explosion)), /LIMIT_EXCEEDED/);

  const oversize = Buffer.alloc(512 * 1024 + 1, 0x61).toString("base64");
  assert.ok(Buffer.byteLength(oversize) < 700 * 1024);
  assert.throws(() => assertCredentialFreeBytes(Buffer.from(oversize)), /LIMIT_EXCEEDED/);

  const controlled = Buffer.from([0, ...Buffer.alloc(15, 0x61)]).toString("base64");
  assert.doesNotThrow(() => assertCredentialFreeBytes(Buffer.from(controlled)));
  assert.doesNotThrow(() => assertCredentialFreeBytes(Buffer.from(
    Buffer.alloc(12, 0x69).toString("base64"),
  )));
  assert.doesNotThrow(() => assertCredentialFreeBytes(Buffer.from("aaaaaaaaaaaaaaaa")));
});

test("credential scan treats exact digests and official evidence strings as ordinary text", () => {
  const digest64 = "8037345fc17999076562acccf519e4b16f13f28e51c780da17c77f4f9bd3e53b";
  const digest40 = `80${"a".repeat(38)}`;
  for (const value of [
    digest40,
    digest64,
    "https://github.com/owner/repo/actions/runs/4001/job/5001",
    "google.iam.admin.v1.DisableServiceAccountKey",
    "type.googleapis.com/google.cloud.audit.AuditLog",
    "google.identity.sts.v1.SecurityTokenService.ExchangeToken",
    "type.googleapis.com/google.identity.sts.v1.ExchangeTokenRequest",
  ]) assert.doesNotThrow(() => assertCredentialFreeBytes(Buffer.from(value)));

  for (const nearDigest of [
    `${digest40.slice(0, -1)}g`,
    `${digest64.slice(0, -1)}A`,
    digest40.slice(0, -1),
    `${digest64}a`,
  ]) {
    assert.throws(
      () => assertCredentialFreeBytes(Buffer.from(nearDigest)),
      { message: "UNSUPPORTED_ENCODED_PAYLOAD" },
    );
  }
});

test("credential scan treats parsed decimal identifiers as text without weakening encoded-byte checks", () => {
  for (const runId of ["80", "8001", "80999999999999999999"]) {
    assert.doesNotThrow(() => assertCredentialFreeBytes(Buffer.from(JSON.stringify({ run_id: runId }))));
  }
  assert.throws(
    () => assertCredentialFreeBytes(Buffer.from("8001")),
    { message: "UNSUPPORTED_ENCODED_PAYLOAD" },
  );
  assert.throws(
    () => assertCredentialFreeBytes(Buffer.from(
      Buffer.concat([Buffer.from("8001"), Buffer.alloc(8, 0x61)]).toString("base64"),
    )),
    { message: "UNSUPPORTED_ENCODED_PAYLOAD" },
  );
  const encodedJson = JSON.stringify({ run_id: "8001" });
  for (const encodedValue of [
    Buffer.from(encodedJson).toString("base64"),
    encodeURIComponent(encodedJson),
  ]) {
    assert.throws(
      () => assertCredentialFreeBytes(Buffer.from(encodedValue)),
      { message: "UNSUPPORTED_ENCODED_PAYLOAD" },
    );
  }
  const adjacent = `1234:gh${"p"}_${"q".repeat(24)}`;
  assert.throws(
    () => assertCredentialFreeBytes(Buffer.from(JSON.stringify({ run_id: "8001", note: adjacent }))),
    (error) => error.message === "credential-shaped material detected" && !error.message.includes(adjacent),
  );
  const compressedAdjacent = `8001gh${"p"}_${"q".repeat(24)}`;
  assert.throws(
    () => assertCredentialFreeBytes(Buffer.from(JSON.stringify({ note: compressedAdjacent }))),
    (error) => error.message === "UNSUPPORTED_ENCODED_PAYLOAD"
      && !error.message.includes(compressedAdjacent),
  );
  assert.throws(
    () => assertCredentialFreeBytes(Buffer.from(JSON.stringify({ "8001": "clean" }))),
    { message: "UNSUPPORTED_ENCODED_PAYLOAD" },
  );
});

test("credential scan keeps strict transform provenance independent of sibling order", () => {
  const encodedId = Buffer.from("8001").toString("base64");
  for (const input of [
    { a_direct: "8001", z_base64: encodedId },
    { a_base64: encodedId, z_direct: "8001" },
  ]) {
    assert.throws(
      () => assertCredentialFreeBytes(Buffer.from(JSON.stringify(input))),
      { message: "UNSUPPORTED_ENCODED_PAYLOAD" },
    );
  }

  const controls = Buffer.concat([Buffer.from([0]), Buffer.alloc(11, 0x61)]);
  const encodedControls = controls.toString("base64");
  const urlControls = [...controls]
    .map((byte) => `%${byte.toString(16).padStart(2, "0")}`).join("");
  for (const input of [
    { a_base64: encodedControls, z_url: urlControls },
    { a_url: urlControls, z_base64: encodedControls },
  ]) {
    assert.throws(
      () => assertCredentialFreeBytes(Buffer.from(JSON.stringify(input))),
      { message: "UNSUPPORTED_ENCODED_PAYLOAD" },
    );
  }
});

test("credential scan grants decimal authority only to the initial parsed JSON tree", () => {
  for (const input of [
    { outer: { values: [{ run_id: "8001" }] } },
    { values: ["8001", { other_id: "8099" }] },
  ]) {
    assert.doesNotThrow(() => assertCredentialFreeBytes(Buffer.from(JSON.stringify(input))));
  }

  const reparsed = [
    JSON.stringify({ run_id: "8001" }),
    JSON.stringify({ "8001": "clean" }),
    JSON.stringify("8001"),
  ];
  for (const nested of reparsed) {
    for (const input of [
      { a_direct: "8001", z_nested: nested },
      { a_nested: nested, z_direct: "8001" },
    ]) {
      assert.throws(
        () => assertCredentialFreeBytes(Buffer.from(JSON.stringify(input))),
        { message: "UNSUPPORTED_ENCODED_PAYLOAD" },
      );
    }
  }
});

test("credential scan retains layered base64 credential and binary-wrapper detection", () => {
  const encoders = [
    (bytes) => bytes.toString("base64"),
    (bytes) => bytes.toString("base64").replace(/=+$/, ""),
    (bytes) => bytes.toString("base64url"),
  ];
  for (const encode of encoders) {
    for (let layers = 1; layers <= 4; layers += 1) {
      let encoded = githubToken;
      for (let layer = 0; layer < layers; layer += 1) encoded = encode(Buffer.from(encoded));
      assert.throws(() => assertCredentialFreeBytes(Buffer.from(encoded)), /credential-shaped/);
    }
  }
  const wrapped = Buffer.concat([Buffer.from([0xff]), Buffer.from(githubToken), Buffer.from([0xfe])]);
  assert.throws(
    () => assertCredentialFreeBytes(Buffer.from(wrapped.toString("base64"))),
    /credential-shaped/,
  );
});

test("credential scan bounds iterative JSON depth, nodes, and strings without leaking input", () => {
  const nested = (depth) => `${"[".repeat(depth)}"clean"${"]".repeat(depth)}`;
  assert.doesNotThrow(() => assertCredentialFreeBytes(Buffer.from(nested(64))));
  assert.throws(
    () => assertCredentialFreeBytes(Buffer.from(nested(65))),
    { message: "CREDENTIAL_SCAN_LIMIT_EXCEEDED" },
  );
  for (const depth of [10_000, 50_000]) {
    const input = nested(depth);
    assert.throws(
      () => assertCredentialFreeBytes(Buffer.from(input)),
      (error) => error.message === "CREDENTIAL_SCAN_LIMIT_EXCEEDED" && !error.message.includes("clean"),
    );
  }
  const wide = Object.fromEntries(Array.from({ length: 5_000 }, (_, index) => [`field_${index}`, index]));
  assert.throws(
    () => assertCredentialFreeBytes(Buffer.from(JSON.stringify(wide))),
    { message: "CREDENTIAL_SCAN_LIMIT_EXCEEDED" },
  );
  const manyStrings = Array.from({ length: 9_000 }, (_, index) => `v${index}`);
  assert.throws(
    () => assertCredentialFreeBytes(Buffer.from(JSON.stringify(manyStrings))),
    { message: "CREDENTIAL_SCAN_LIMIT_EXCEEDED" },
  );
});
