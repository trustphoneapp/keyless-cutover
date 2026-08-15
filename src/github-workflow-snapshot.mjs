import { createHash } from "node:crypto";

import { looksCredentialShaped } from "./credential-shaped.mjs";

export function githubWorkflowSnapshot(content) {
  if (content?.encoding !== "base64" || typeof content.content !== "string"
      || !/^[a-f0-9]{40}$/.test(content.sha ?? "")) {
    throw new Error("GitHub workflow content is invalid");
  }
  const bytes = Buffer.from(content.content.replace(/\s/g, ""), "base64");
  if (!bytes.length || bytes.length > 64 * 1024) throw new Error("GitHub workflow size is invalid");
  const text = bytes.toString("utf8");
  if (text.includes("\0") || looksCredentialShaped(text)) {
    throw new Error("GitHub workflow content is invalid");
  }
  return {
    bytes,
    workflow_blob_sha: content.sha,
    workflow_sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

export function githubReleaseMarker(content) {
  if (content?.encoding !== "base64" || typeof content.content !== "string"
      || !/^[a-f0-9]{40}$/.test(content.sha ?? "")) {
    throw new Error("GitHub release marker content is invalid");
  }
  const decoded = Buffer.from(content.content.replace(/\s/g, ""), "base64").toString("utf8");
  if (decoded.includes("\0")) throw new Error("GitHub release marker is invalid");
  const normalized = decoded.replace(/^\uFEFF/, "");
  const value = /\r?\n$/.test(normalized) && !/\r?\n.+\r?\n$/s.test(normalized)
    ? normalized.replace(/\r?\n$/, "")
    : normalized;
  if (!value || /[\r\n]/.test(value) || !/^[a-z0-9][a-z0-9-]{0,19}$/.test(value)) {
    throw new Error("GitHub release marker is invalid");
  }
  return value;
}
