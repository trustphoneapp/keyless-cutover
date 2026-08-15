import assert from "node:assert/strict";
import test from "node:test";

import { requireGitHubInstallationToken, requireGitHubReadToken } from "../src/github-token.mjs";

test("accepts classic and stateless GitHub installation token formats", () => {
  const classic = `ghs_${"a".repeat(36)}`;
  const stateless = `ghs_${"a".repeat(171)}.${"b".repeat(171)}.${"c".repeat(172)}`;

  assert.equal(stateless.length, 520);
  assert.equal(requireGitHubInstallationToken(classic), classic);
  assert.equal(requireGitHubInstallationToken(stateless), stateless);
});

test("treats installation tokens as bounded opaque credentials", () => {
  assert.throws(() => requireGitHubInstallationToken("github-installation-token-value"), /invalid/);
  assert.throws(() => requireGitHubInstallationToken(`ghs_${"a".repeat(20)} whitespace`), /invalid/);
  assert.throws(() => requireGitHubInstallationToken(`ghs_${"a".repeat(4093)}`), /invalid/);
});

test("allows a bounded GitHub OAuth token only for read-side operator evidence", () => {
  const oauth = `gho_${"a".repeat(36)}`;
  assert.equal(requireGitHubReadToken(oauth), oauth);
  assert.equal(requireGitHubReadToken(`ghs_${"a".repeat(36)}`), `ghs_${"a".repeat(36)}`);
  assert.throws(() => requireGitHubInstallationToken(oauth), /installation token/);
  assert.throws(() => requireGitHubReadToken(`gho_${"a".repeat(35)}`), /read token/);
});

test("refuses write and user PAT token shapes for installation and read helpers", () => {
  for (const value of [
    `ghp_${"a".repeat(36)}`,
    `ghu_${"a".repeat(36)}`,
    `ghr_${"a".repeat(36)}`,
    `github_pat_${"a".repeat(40)}`,
  ]) {
    assert.throws(() => requireGitHubInstallationToken(value), /invalid/);
    assert.throws(() => requireGitHubReadToken(value), /invalid/);
  }
});
