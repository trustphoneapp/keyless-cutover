const INSTALLATION_TOKEN = /^ghs_[A-Za-z0-9._-]{36,4092}$/;
const OAUTH_TOKEN = /^gho_[A-Za-z0-9_]{36}$/;
const REJECTED_WRITE_SHAPES = /^(?:ghp_|ghu_|ghr_|github_pat_)/;

function refuseWriteShapedToken(value) {
  if (typeof value === "string" && REJECTED_WRITE_SHAPES.test(value)) {
    throw new Error("GitHub read token is invalid");
  }
}

export function requireGitHubInstallationToken(value) {
  refuseWriteShapedToken(value);
  if (typeof value !== "string" || !INSTALLATION_TOKEN.test(value)) {
    throw new Error("GitHub installation token is invalid");
  }
  return value;
}

export function requireGitHubReadToken(value) {
  refuseWriteShapedToken(value);
  if (typeof value !== "string" || (!INSTALLATION_TOKEN.test(value) && !OAUTH_TOKEN.test(value))) {
    throw new Error("GitHub read token is invalid");
  }
  return value;
}
