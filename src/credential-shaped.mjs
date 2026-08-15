// Shared fail-closed denylist for API/manifest/workflow text surfaces.
// Keep aligned with src/credential-scan.mjs PATTERNS for PEM and token shapes.
export const CREDENTIAL_SHAPED = /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----|["']?private[_-]?key["']?\s*[:=]|ya29\.[A-Za-z0-9._-]+|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|xapp-[0-9]+-[A-Za-z0-9-]{10,}|bearer\s+[A-Za-z0-9._~+/=-]{20,})/i;

export function looksCredentialShaped(value) {
  return typeof value === "string" && value.length > 0 && CREDENTIAL_SHAPED.test(value);
}
