import assert from "node:assert/strict";
import test from "node:test";

import { looksCredentialShaped } from "../src/credential-shaped.mjs";
import { textLooksLikeCredential } from "../src/credential-scan.mjs";

test("credential-shaped and credential-scan agree on explicit credential samples", () => {
  const positives = [
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    'private-key: "x"',
    `ghp_${"a".repeat(36)}`,
    `github_pat_${"b".repeat(36)}`,
    `ya29.${"c".repeat(30)}`,
    `AIza${"d".repeat(35)}`,
    `AKIA${"E".repeat(16)}`,
    "xoxb-1234567890-abcdefghij",
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
    "bearer abcdefghijklmnopqrstuvwxyz012345",
  ];
  for (const sample of positives) {
    assert.equal(looksCredentialShaped(sample), true, sample);
    assert.equal(textLooksLikeCredential(sample), true, sample);
  }
  assert.equal(looksCredentialShaped("run_id 8001"), false);
  assert.equal(textLooksLikeCredential("run_id 8001"), false);
  // Scan keeps word boundaries so compressed adjacency is not a credential hit.
  assert.equal(textLooksLikeCredential(`8001ghp_${"q".repeat(24)}`), false);
  assert.equal(looksCredentialShaped(`8001ghp_${"q".repeat(24)}`), true);
});
