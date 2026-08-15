import { isRfc3339, timestampNanoseconds } from "./rfc3339.mjs";

const HTTP_DATE = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{2}):(\d{2}):(\d{2}) GMT$/;
const MONTHS = new Map([
  ["Jan", 0], ["Feb", 1], ["Mar", 2], ["Apr", 3], ["May", 4], ["Jun", 5],
  ["Jul", 6], ["Aug", 7], ["Sep", 8], ["Oct", 9], ["Nov", 10], ["Dec", 11],
]);
const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

export function rejectDuplicateJsonKeys(text) {
  let index = 0;
  const whitespace = () => { while (/[\t\n\r ]/.test(text[index] ?? "")) index += 1; };
  const string = () => {
    const start = index;
    if (text[index] !== '"') throw new Error("invalid JSON");
    index += 1;
    for (;;) {
      const character = text[index];
      if (character === undefined || /[\u0000-\u001f]/u.test(character)) throw new Error("invalid JSON");
      if (character === '"') {
        index += 1;
        return JSON.parse(text.slice(start, index));
      }
      if (character === "\\") {
        index += 1;
        if (!/["\\/bfnrtu]/.test(text[index] ?? "")) throw new Error("invalid JSON");
        if (text[index] === "u") {
          if (!/^[a-f0-9]{4}$/i.test(text.slice(index + 1, index + 5))) throw new Error("invalid JSON");
          index += 4;
        }
      }
      index += 1;
    }
  };
  const value = (depth) => {
    if (depth > 64) throw new Error("invalid JSON");
    whitespace();
    if (text[index] === "{") {
      index += 1;
      whitespace();
      const keys = new Set();
      if (text[index] === "}") { index += 1; return; }
      for (;;) {
        whitespace();
        const key = string();
        if (keys.has(key)) throw new Error("duplicate JSON key");
        keys.add(key);
        whitespace();
        if (text[index] !== ":") throw new Error("invalid JSON");
        index += 1;
        value(depth + 1);
        whitespace();
        if (text[index] === "}") { index += 1; return; }
        if (text[index] !== ",") throw new Error("invalid JSON");
        index += 1;
      }
    }
    if (text[index] === "[") {
      index += 1;
      whitespace();
      if (text[index] === "]") { index += 1; return; }
      for (;;) {
        value(depth + 1);
        whitespace();
        if (text[index] === "]") { index += 1; return; }
        if (text[index] !== ",") throw new Error("invalid JSON");
        index += 1;
      }
    }
    if (text[index] === '"') { string(); return; }
    for (const literal of ["true", "false", "null"]) {
      if (text.startsWith(literal, index)) { index += literal.length; return; }
    }
    const number = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(index));
    if (!number) throw new Error("invalid JSON");
    index += number[0].length;
  };
  value(0);
  whitespace();
  if (index !== text.length) throw new Error("invalid JSON");
}

export function parseAuthenticatedTransportObservation(response, options = {}) {
  if (!options || typeof options !== "object" || Array.isArray(options)
      || Object.getPrototypeOf(options) !== Object.prototype
      || Object.keys(options).some((key) => !["expectedStatus", "sourceEventTimes"].includes(key))) {
    throw new Error("authenticated transport observation options are invalid");
  }
  const { expectedStatus, sourceEventTimes = [] } = options;
  if (!response || response.ok !== true || !Number.isInteger(response.status)
      || response.status < 200 || response.status > 299
      || !Number.isInteger(expectedStatus) || expectedStatus < 200 || expectedStatus > 299
      || response.status !== expectedStatus
      || !response.headers || typeof response.headers.get !== "function") {
    throw new Error("authenticated transport response is invalid");
  }
  const value = response.headers.get("date");
  if (typeof value !== "string" || value.indexOf(",") !== value.lastIndexOf(",")) {
    throw new Error("authenticated transport Date header is invalid");
  }
  const match = HTTP_DATE.exec(value);
  if (!match) throw new Error("authenticated transport Date header is invalid");
  const [, weekday, dayText, monthText, yearText, hourText, minuteText, secondText] = match;
  const year = Number(yearText);
  const month = MONTHS.get(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  if (year < 1601 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) {
    throw new Error("authenticated transport Date header is invalid");
  }
  const milliseconds = Date.UTC(year, month, day, hour, minute, second);
  const parsed = new Date(milliseconds);
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month || parsed.getUTCDate() !== day
      || parsed.getUTCHours() !== hour || parsed.getUTCMinutes() !== minute || parsed.getUTCSeconds() !== second
      || WEEKDAYS[parsed.getUTCDay()] !== weekday) {
    throw new Error("authenticated transport Date header is invalid");
  }
  if (!Array.isArray(sourceEventTimes) || sourceEventTimes.length > 100) {
    throw new Error("authenticated transport source times are invalid");
  }
  const observedAt = `${String(year).padStart(4, "0")}-${String(month + 1).padStart(2, "0")}-${String(day).padStart(2, "0")}T${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}:${String(second).padStart(2, "0")}.000Z`;
  if (!isRfc3339(observedAt) || timestampNanoseconds(observedAt) !== BigInt(milliseconds) * 1_000_000n) {
    throw new Error("authenticated transport Date header is invalid");
  }
  const observed = timestampNanoseconds(observedAt);
  for (const eventTime of sourceEventTimes) {
    if (!isRfc3339(eventTime) || timestampNanoseconds(eventTime) > observed) {
      throw new Error("authenticated transport observation regresses from its source event");
    }
  }
  return observedAt;
}
