const INSTALLATION_TOKEN = /^ghs_[A-Za-z0-9._-]{36,4092}$/;

export function requireGitHubInstallationToken(value) {
  if (typeof value !== "string" || !INSTALLATION_TOKEN.test(value)) {
    throw new Error("GitHub installation token is invalid");
  }
  return value;
}
