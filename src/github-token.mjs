const INSTALLATION_TOKEN = /^ghs_[A-Za-z0-9._-]{36,4092}$/;
const OAUTH_TOKEN = /^gho_[A-Za-z0-9_]{36}$/;

export function requireGitHubInstallationToken(value) {
  if (typeof value !== "string" || !INSTALLATION_TOKEN.test(value)) {
    throw new Error("GitHub installation token is invalid");
  }
  return value;
}

export function requireGitHubReadToken(value) {
  if (typeof value !== "string" || (!INSTALLATION_TOKEN.test(value) && !OAUTH_TOKEN.test(value))) {
    throw new Error("GitHub read token is invalid");
  }
  return value;
}
