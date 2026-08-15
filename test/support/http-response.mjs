/** Build a fetch Response with an explicit Content-Length (Node omits it by default). */
export function httpResponse(body, { status = 200, headers = {} } = {}) {
  const bytes = Buffer.isBuffer(body)
    ? body
    : Buffer.from(body === undefined || body === null
      ? ""
      : typeof body === "string" ? body : JSON.stringify(body));
  return new Response(bytes, {
    status,
    headers: {
      "content-length": String(bytes.length),
      ...headers,
    },
  });
}

/** Lightweight mock used by tests that do not construct a real Response. */
export function mockJsonResponse(value, { status = 200, ok = status >= 200 && status < 300, headers = {} } = {}) {
  const text = value === undefined || value === null
    ? ""
    : typeof value === "string" ? value : JSON.stringify(value);
  const headerMap = {
    "content-length": String(Buffer.byteLength(text)),
    ...headers,
  };
  return {
    ok,
    status,
    headers: {
      get(name) {
        const key = String(name).toLowerCase();
        const found = Object.entries(headerMap).find(([entry]) => entry.toLowerCase() === key);
        return found ? String(found[1]) : null;
      },
    },
    text: async () => text,
  };
}
