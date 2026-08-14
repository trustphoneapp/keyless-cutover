import assert from "node:assert/strict";
import test from "node:test";

import { parseAuthenticatedTransportObservation } from "../src/observation-time.mjs";

function response(date, status = 200) {
  return new Response("{}", { status, headers: date === undefined ? {} : { date } });
}

test("authenticated transport observation derives canonical time only from one HTTP Date header", () => {
  const value = parseAuthenticatedTransportObservation(
    response("Thu, 13 Aug 2026 12:14:00 GMT"),
    { expectedStatus: 200, sourceEventTimes: ["2026-08-13T12:13:59.999999999Z"] },
  );
  assert.equal(value, "2026-08-13T12:14:00.000Z");
  assert.throws(() => parseAuthenticatedTransportObservation(response(
    "Thu, 13 Aug 2026 12:14:00 GMT",
  ), {
    expectedStatus: 200,
    observedAt: "2026-08-13T12:14:00Z",
  }), /options/);
});

test("authenticated transport observation rejects absent, ambiguous, malformed, and wrong-status responses", () => {
  const multiple = new Headers();
  multiple.append("date", "Thu, 13 Aug 2026 12:14:00 GMT");
  multiple.append("date", "Thu, 13 Aug 2026 12:14:01 GMT");
  const cases = [
    response(undefined),
    new Response("{}", { status: 200, headers: multiple }),
    response("Thu, 32 Aug 2026 12:14:00 GMT"),
    response("Fri, 13 Aug 2026 12:14:00 GMT"),
    response("Thu, 13 Aug 2026 12:14:60 GMT"),
    response("Thu, 13 Aug 2026 12:14:00 UTC"),
    response("Thu, 13 Aug 2026 12:14:00 GMT", 201),
    response("Thu, 13 Aug 2026 12:14:00 GMT", 500),
  ];
  for (const value of cases) {
    assert.throws(() => parseAuthenticatedTransportObservation(value, { expectedStatus: 200 }));
  }
});

test("authenticated transport observation requires matching successful integer status bounds", () => {
  const headers = new Headers({ date: "Thu, 13 Aug 2026 12:14:00 GMT" });
  for (const expectedStatus of [0, 199, 300, 700, 200.5]) {
    assert.throws(() => parseAuthenticatedTransportObservation(
      { ok: true, status: expectedStatus, headers }, { expectedStatus },
    ), /response/);
  }
  for (const status of [0, 199, 300, 700, 200.5]) {
    assert.throws(() => parseAuthenticatedTransportObservation(
      { ok: true, status, headers }, { expectedStatus: 200 },
    ), /response/);
  }
  assert.throws(() => parseAuthenticatedTransportObservation(
    { ok: false, status: 200, headers }, { expectedStatus: 200 },
  ), /response/);
  assert.throws(() => parseAuthenticatedTransportObservation(
    { ok: true, status: 201, headers }, { expectedStatus: 200 },
  ), /response/);
});

test("authenticated transport observation rejects future or invalid source event times", () => {
  const value = response("Thu, 13 Aug 2026 12:14:00 GMT");
  for (const sourceEventTimes of [
    ["2026-08-13T12:14:00.000000001Z"],
    ["2026-02-29T12:00:00Z"],
    Array.from({ length: 101 }, () => "2026-08-13T12:13:00Z"),
  ]) {
    assert.throws(() => parseAuthenticatedTransportObservation(value, {
      expectedStatus: 200,
      sourceEventTimes,
    }), /source|regresses/);
  }
});
