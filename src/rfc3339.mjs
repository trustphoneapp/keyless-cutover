const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;

export function timestampNanoseconds(value) {
  const match = typeof value === "string" ? RFC3339.exec(value) : null;
  if (!match) return null;
  const [, year, month, day, hour, minute, second, fraction = ""] = match;
  const whole = `${year}-${month}-${day}T${hour}:${minute}:${second}`;
  const milliseconds = Date.parse(`${whole}Z`);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString().slice(0, 19) !== whole) return null;
  return BigInt(milliseconds / 1000) * 1_000_000_000n + BigInt(fraction.padEnd(9, "0") || "0");
}

export function isRfc3339(value) {
  return timestampNanoseconds(value) !== null;
}

export function timestampBefore(left, right) {
  const leftValue = timestampNanoseconds(left);
  const rightValue = timestampNanoseconds(right);
  return leftValue !== null && rightValue !== null && leftValue < rightValue;
}

export function timestampAtOrBefore(left, right) {
  const leftValue = timestampNanoseconds(left);
  const rightValue = timestampNanoseconds(right);
  return leftValue !== null && rightValue !== null && leftValue <= rightValue;
}

export function formatTimestampNanoseconds(nanos) {
  if (typeof nanos !== "bigint" || nanos < 0n) return null;
  const seconds = nanos / 1_000_000_000n;
  const fraction = nanos % 1_000_000_000n;
  if (seconds > BigInt(Number.MAX_SAFE_INTEGER) / 1000n) return null;
  const wholeMs = Number(seconds) * 1000;
  if (!Number.isSafeInteger(wholeMs)) return null;
  const whole = new Date(wholeMs).toISOString().slice(0, 19);
  if (!Number.isFinite(Date.parse(`${whole}Z`)) || new Date(Date.parse(`${whole}Z`)).toISOString().slice(0, 19) !== whole) {
    return null;
  }
  const frac = fraction.toString().padStart(9, "0").replace(/0+$/, "");
  return frac.length > 0 ? `${whole}.${frac}Z` : `${whole}Z`;
}
