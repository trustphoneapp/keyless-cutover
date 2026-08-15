import assert from "node:assert/strict";
import test from "node:test";

import { formatTimestampNanoseconds, isRfc3339, timestampAtOrBefore, timestampBefore, timestampNanoseconds } from "../src/rfc3339.mjs";

test("RFC3339 parser accepts canonical 0–9 fractional digits without calendar normalization", () => {
  for (const value of [
    "2026-08-13T12:00:00Z",
    "2026-08-13T12:00:00.1Z",
    "2026-08-13T12:00:00.123456789Z",
    "2024-02-29T23:59:59.000000001Z",
  ]) assert.equal(isRfc3339(value), true, value);
  for (const value of [
    "2026-02-29T12:00:00Z",
    "2026-04-31T12:00:00Z",
    "2026-08-13T24:00:00Z",
    "2026-08-13T12:00:60Z",
    "2026-08-13T12:00:00.1234567890Z",
    "2026-08-13T12:00:00+00:00",
  ]) assert.equal(isRfc3339(value), false, value);
  assert.equal(timestampBefore("2026-08-13T12:00:00.000000001Z", "2026-08-13T12:00:00.000000002Z"), true);
  assert.equal(timestampAtOrBefore("2026-08-13T12:00:00.1Z", "2026-08-13T12:00:00.100000000Z"), true);
  assert.equal(
    formatTimestampNanoseconds(timestampNanoseconds("2026-08-13T12:00:00.000000001Z") + 1n),
    "2026-08-13T12:00:00.000000002Z",
  );
  assert.equal(formatTimestampNanoseconds(timestampNanoseconds("2026-08-13T12:00:00Z")), "2026-08-13T12:00:00Z");
});
