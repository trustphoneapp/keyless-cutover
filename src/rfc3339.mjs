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
