const INSTALLATION_TOKEN = /^ghs_[A-Za-z0-9._-]{36,4092}$/;
const OAUTH_TOKEN = /^gho_[A-Za-z0-9_]{36}$/;
const REJECTED_WRITE_SHAPES = /^(?:ghp_|ghu_|ghr_|github_pat_)/;
const REJECTED_PREFIX = /^(?:\s|[\u0000-\u001f\u007f]|Bearer\b|Authorization\b)/i;

function refuseWriteShapedToken(value) {
  if (typeof value === "string" && REJECTED_WRITE_SHAPES.test(value)) {
    throw new Error("GitHub read token is invalid");
  }
}

function requirePlainTokenString(value, name) {
  if (typeof value !== "string" || value.trim() !== value || REJECTED_PREFIX.test(value)
      || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  refuseWriteShapedToken(value);
  return value;
}

export function requireGitHubInstallationToken(value) {
  requirePlainTokenString(value, "GitHub installation token");
  if (!INSTALLATION_TOKEN.test(value)) {
    throw new Error("GitHub installation token is invalid");
  }
  return value;
}

export function requireGitHubReadToken(value) {
  requirePlainTokenString(value, "GitHub read token");
  if (!INSTALLATION_TOKEN.test(value) && !OAUTH_TOKEN.test(value)) {
    throw new Error("GitHub read token is invalid");
  }
  return value;
}
