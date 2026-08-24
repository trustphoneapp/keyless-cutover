import assert from "node:assert/strict";
import test from "node:test";
import AdmZip from "adm-zip";

import {
  collectGitHubDenialEvidence,
  downloadGitHubBytes,
  downloadGitHubBytesObserved,
  fetchGitHubJson,
  fetchGitHubJsonObserved,
} from "../src/github-denial-evidence.mjs";

const installationToken = `ghs_${"t".repeat(36)}`;
const provider = "projects/3/locations/global/workloadIdentityPools/keyless/providers/github";
const federated = (name) => `failed to generate Google Cloud federated token for //iam.googleapis.com/${name}:`;

function response(status, value, extraHeaders = {}) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
  return new Response(bytes, {
    status,
    headers: { date: "Thu, 13 Aug 2026 11:10:00 GMT", ...extraHeaders },
  });
}

async function assertStaticFailure(operation, marker, pattern) {
  let error;
  try { await operation(); } catch (caught) { error = caught; }
  assert.ok(error);
  assert.match(error.message, pattern);
  assert.equal(error.message.includes(marker), false);
  assert.equal(error.message.includes(installationToken), false);
}

function fixture(options = {}) {
  const {
    log = `google-github-actions/auth ${federated(provider)} audience rejected by Security Token Service`,
    mutateRun,
    mutateJobs,
    mutateArtifacts,
  } = typeof options === "string" ? { log: options } : options;
  const workflow = "name: hostile\n";
  const run = {
    id: 7007, run_attempt: 1, status: "completed", conclusion: "success", head_sha: "a".repeat(40),
    head_branch: "main", path: ".github/workflows/k0-deploy.yml", event: "push",
    run_started_at: "2026-08-13T11:00:00.123456789Z", actor: { id: 10 },
    repository: { id: 2, full_name: "trustphoneapp/keyless-cutover", owner: { id: 1 } },
  };
  const denial = {
    version: 1, id: "H7", outcome: "failure", run_id: "7007", run_attempt: "1", head_sha: "a".repeat(40),
    workflow_ref: "trustphoneapp/keyless-cutover/.github/workflows/k0-deploy.yml@refs/heads/main",
    event: "push", ref: "refs/heads/main", environment: "production",
    audience: "https://iam.googleapis.com/projects/0/locations/global/workloadIdentityPools/wrong/providers/wrong",
  };
  const zip = new AdmZip();
  zip.addFile("k0-H7.json", Buffer.from(JSON.stringify(denial)));
  const jobsResponse = { total_count: 1, jobs: [{
    id: 77, name: "h7-wrong-audience", status: "completed", conclusion: "success",
    runner_group_name: "GitHub Actions", labels: ["ubuntu-latest"],
    started_at: "2026-08-13T11:00:30.123456789Z",
    completed_at: "2026-08-13T11:01:00.123456789Z",
    steps: [{ name: "Require H7 denial", conclusion: "success" }],
  }] };
  const artifactsResponse = {
    total_count: 1,
    artifacts: [{ id: 88, name: "keyless-h7-denial", expired: false }],
  };
  mutateRun?.(run);
  mutateJobs?.(jobsResponse);
  mutateArtifacts?.(artifactsResponse);
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, authorization: options.headers?.authorization });
    if (url.endsWith("/actions/runs/7007")) return response(200, run);
    if (url.includes("/jobs?")) return response(200, jobsResponse);
    if (url.includes("/artifacts?")) return response(200, artifactsResponse);
    if (url.endsWith("/actions/artifacts/88/zip")) return response(302, "", { location: "https://objects.githubusercontent.com/artifact.zip" });
    if (url.endsWith("/actions/jobs/77/logs")) return response(302, "", { location: "https://objects.githubusercontent.com/job.txt" });
    if (url.endsWith("artifact.zip")) return response(200, zip.toBuffer(), { "content-length": String(zip.toBuffer().length) });
    if (url.endsWith("job.txt")) return response(200, log, { "content-length": String(log.length) });
    if (url.includes("/contents/demo/release.txt")) return response(200, { encoding: "base64", content: Buffer.from("wif-1\n").toString("base64") });
    if (url.includes("/contents/")) return response(200, { encoding: "base64", content: Buffer.from(workflow).toString("base64"), sha: "c".repeat(40) });
    throw new Error(`unexpected URL ${url}`);
  };
  return { fetchImpl, requests };
}

function h2Fixture() {
  const workflow = "name: external hostile\n";
  const run = {
    id: 8002, run_attempt: 1, status: "completed", conclusion: "success", head_sha: "b".repeat(40),
    head_branch: "main", path: ".github/workflows/k0-external-hostile.yml", event: "push",
    run_started_at: "2026-08-13T11:00:00Z", actor: { id: 10 },
    repository: { id: 22, full_name: "trustphoneapp/keyless-hostile", owner: { id: 1 } },
  };
  const denial = {
    version: 1, id: "H2", outcome: "failure", run_id: "8002", run_attempt: "1", head_sha: "b".repeat(40),
    workflow_ref: "trustphoneapp/keyless-hostile/.github/workflows/k0-external-hostile.yml@refs/heads/main",
    event: "push", ref: "refs/heads/main", environment: "production", owner_id: "1", repository_id: "22",
  };
  const zip = new AdmZip();
  zip.addFile("k0-external.json", Buffer.from(JSON.stringify(denial)));
  const log = `google-github-actions/auth ${federated(provider)} credential is rejected by the attribute condition at STS`;
  const fetchImpl = async (url) => {
    if (url.endsWith("/actions/runs/8002")) return response(200, run);
    if (url.includes("/jobs?")) return response(200, { total_count: 1, jobs: [{
      id: 82, name: "external-identity", status: "completed", conclusion: "success",
      runner_group_name: "GitHub Actions", labels: ["ubuntu-latest"],
      started_at: "2026-08-13T11:00:30Z",
      completed_at: "2026-08-13T11:01:00Z",
      steps: [{ name: "Require external identity denial", conclusion: "success" }],
    }] });
    if (url.includes("/artifacts?")) return response(200, { total_count: 1, artifacts: [{ id: 92, name: "keyless-external-denial", expired: false }] });
    if (url.endsWith("/actions/artifacts/92/zip")) return response(302, "", { location: "https://objects.githubusercontent.com/h2.zip" });
    if (url.endsWith("/actions/jobs/82/logs")) return response(302, "", { location: "https://objects.githubusercontent.com/h2.txt" });
    if (url.endsWith("h2.zip")) return response(200, zip.toBuffer(), { "content-length": String(zip.toBuffer().length) });
    if (url.endsWith("h2.txt")) return response(200, log, { "content-length": String(log.length) });
    if (url.includes("/contents/demo/release.txt")) return response(200, { encoding: "base64", content: Buffer.from("external\n").toString("base64") });
    if (url.includes("/contents/")) return response(200, { encoding: "base64", content: Buffer.from(workflow).toString("base64"), sha: "d".repeat(40) });
    throw new Error(`unexpected URL ${url}`);
  };
  return fetchImpl;
}

const input = {
  owner: "trustphoneapp", repository: "keyless-cutover", runId: "7007", hostileId: "H7",
  installationToken, scopeOwnerId: "1", scopeRepositoryId: "2",
  forbiddenService: "keyless-forbidden", provider,
};

test("GitHub collector proves a hostile denial from API, artifact, and allowlisted log signature", async () => {
  const { fetchImpl, requests } = fixture();
  const result = await collectGitHubDenialEvidence({ ...input, fetchImpl });
  assert.equal(result.githubRun.run_id, "7007");
  assert.equal(result.githubRun.environment, "production");
  assert.equal(result.clientResult.hostile_id, "H7");
  assert.equal(result.clientResult.error_category, "AUDIENCE_DENIED");
  assert.equal(result.clientResult.reached_sts, true);
  assert.equal(result.clientResult.run_attempt, "1");
  assert.equal(result.clientResult.denied_at, "2026-08-13T11:01:00.123456789Z");
  assert.equal(result.observedAt, "2026-08-13T11:10:00Z");
  assert.equal(result.githubRun.release_marker, "wif-1");
  assert.match(result.githubRun.workflow_sha256, /^[a-f0-9]{64}$/);
  assert.match(result.clientResult.log_sha256, /^[a-f0-9]{64}$/);
  assert.equal(requests.filter(({ url }) => url.startsWith("https://objects.githubusercontent.com"))
    .every(({ authorization }) => authorization === undefined), true);
});

test("GitHub collector accepts a bounded OAuth token only for read-side evidence", async () => {
  const { fetchImpl } = fixture();
  const result = await collectGitHubDenialEvidence({
    ...input,
    installationToken: `gho_${"t".repeat(36)}`,
    fetchImpl,
  });
  assert.equal(result.clientResult.error_category, "AUDIENCE_DENIED");
});

test("GitHub collector refuses a generic failure before the intended control", async () => {
  const { fetchImpl } = fixture(`network timeout before authentication ${federated(provider)}`);
  await assert.rejects(collectGitHubDenialEvidence({ ...input, fetchImpl }), /does not prove/);
});

test("GitHub collector refuses a denial issued by a different WIF provider", async () => {
  const other = "projects/3/locations/global/workloadIdentityPools/keyless/providers/github-fresh-wif1";
  const wrongProvider = fixture(`google-github-actions/auth ${federated(other)} audience rejected by Security Token Service`);
  await assert.rejects(collectGitHubDenialEvidence({ ...input, fetchImpl: wrongProvider.fetchImpl }), /approved WIF provider/);
  const noProvider = fixture("google-github-actions/auth failed: audience rejected by Security Token Service");
  await assert.rejects(collectGitHubDenialEvidence({ ...input, fetchImpl: noProvider.fetchImpl }), /approved WIF provider/);
  const { fetchImpl } = fixture();
  await assert.rejects(collectGitHubDenialEvidence({ ...input, provider: undefined, fetchImpl }), /WIF provider is invalid/);
  const ok = await collectGitHubDenialEvidence({ ...input, fetchImpl });
  assert.equal(ok.clientResult.provider, provider);
});

test("GitHub collector requires authoritative GitHub-hosted runner metadata", async () => {
  for (const mutateJobs of [
    (page) => { page.jobs[0].runner_group_name = "Self-hosted"; },
    (page) => { page.jobs[0].labels = ["linux", "x64"]; },
  ]) {
    const { fetchImpl } = fixture({ mutateJobs });
    await assert.rejects(collectGitHubDenialEvidence({ ...input, fetchImpl }), /hostile job/);
  }
});

test("GitHub collector rejects run and job events outside the authoritative timeline", async () => {
  const attacks = [
    { mutateRun: (run) => { run.run_started_at = "2026-08-13T11:02:00Z"; } },
    { mutateJobs: (page) => { page.jobs[0].started_at = "2026-08-13T10:59:00Z"; } },
    { mutateJobs: (page) => { page.jobs[0].started_at = "2026-08-13T11:02:00Z"; } },
    { mutateJobs: (page) => { page.jobs[0].completed_at = "2026-08-13T10:59:00Z"; } },
  ];
  for (const options of attacks) {
    const { fetchImpl } = fixture(options);
    await assert.rejects(() => collectGitHubDenialEvidence({ ...input, fetchImpl }), /timeline/);
  }
});

test("GitHub collector rejects incomplete or ambiguous bounded job and artifact pages", async () => {
  const pages = ["Jobs", "Artifacts"];
  const mutations = [
    (page) => { delete page.total_count; },
    (page) => { page.total_count = 0; },
    (page) => { page.total_count = 2; },
    (page) => {
      const field = page.jobs ? "jobs" : "artifacts";
      page[field].push(...Array.from({ length: 100 }, (_, index) => ({ id: 1_000 + index, name: `other-${index}` })));
      page.total_count = 101;
    },
    (page) => {
      const field = page.jobs ? "jobs" : "artifacts";
      page[field].push({ ...page[field][0], id: page[field][0].id + 1 });
      page.total_count = 2;
    },
  ];
  for (const pageName of pages) {
    for (const mutation of mutations) {
      const option = `mutate${pageName}`;
      const { fetchImpl } = fixture({ [option]: mutation });
      await assert.rejects(collectGitHubDenialEvidence({ ...input, fetchImpl }));
    }
  }
});

test("GitHub collector proves H2 from the intended owner and a different repository ID", async () => {
  const result = await collectGitHubDenialEvidence({
    ...input,
    repository: "keyless-hostile",
    runId: "8002",
    hostileId: "H2",
    scopeRepositoryId: "2",
    fetchImpl: h2Fixture(),
  });
  assert.equal(result.githubRun.owner_id, "1");
  assert.equal(result.githubRun.repository_id, "22");
  assert.equal(result.clientResult.hostile_id, "H2");
  assert.equal(result.clientResult.error_category, "WIF_CONDITION_DENIED");
});

test("observed GitHub transports are bounded, canonical, and keep old return shapes", async () => {
  const jsonFetch = async () => response(200, { ok: true });
  assert.deepEqual(await fetchGitHubJson("https://api.github.com/example", installationToken, jsonFetch), { ok: true });
  assert.deepEqual(await fetchGitHubJsonObserved("https://api.github.com/example", installationToken, jsonFetch), {
    value: { ok: true },
    observedAt: "2026-08-13T11:10:00Z",
  });

  const binaryFetch = async (url) => url.includes("api.github.com")
    ? response(302, "", { location: "https://objects.githubusercontent.com/example.bin" })
    : response(200, "safe evidence", { date: "Thu, 13 Aug 2026 11:11:00 GMT" });
  assert.equal((await downloadGitHubBytes("https://api.github.com/download", installationToken, binaryFetch, 100)).toString(), "safe evidence");
  const observed = await downloadGitHubBytesObserved(
    "https://api.github.com/download", installationToken, binaryFetch, 100,
  );
  assert.equal(observed.bytes.toString(), "safe evidence");
  assert.equal(observed.observedAt, "2026-08-13T11:11:00Z");
});

test("collector observedAt is the latest authenticated transport response", async () => {
  const { fetchImpl } = fixture();
  const dates = new Map([
    ["artifact.zip", "Thu, 13 Aug 2026 11:12:00 GMT"],
    ["job.txt", "Thu, 13 Aug 2026 11:13:00 GMT"],
    ["/contents/demo/release.txt", "Thu, 13 Aug 2026 11:15:00 GMT"],
  ]);
  const collected = await collectGitHubDenialEvidence({
    ...input,
    fetchImpl: async (url, options) => {
      const original = await fetchImpl(url, options);
      const bytes = await original.arrayBuffer();
      const headers = Object.fromEntries(original.headers.entries());
      for (const [fragment, date] of dates) {
        if (url.includes(fragment)) headers.date = date;
      }
      return new Response(bytes, { status: original.status, headers });
    },
  });
  assert.equal(collected.observedAt, "2026-08-13T11:15:00Z");
});

test("observed JSON transport rejects bad time, status, UTF-8, duplicate keys, and malformed JSON", async () => {
  const attacks = [
    response(200, {}, { date: "" }),
    response(200, {}, { date: "2026-08-13T11:10:00Z" }),
    response(201, {}),
    response(200, Buffer.from([0xff])),
    response(200, '{"outer":{"a":1,"\\u0061":2}}'),
    response(200, "{"),
  ];
  for (const attack of attacks) {
    await assert.rejects(() => fetchGitHubJsonObserved(
      "https://api.github.com/example", installationToken, async () => attack,
    ));
  }
});

test("observed JSON transport replaces arbitrary fetch rejection values with a static error", async () => {
  const marker = `json-fetch-marker-${installationToken}`;
  const hostileProxy = new Proxy({}, {
    get() { throw new Error(`proxy getter leaked ${marker}`); },
  });
  const attacks = [
    () => { throw new Error(`error leaked ${marker}`); },
    () => Promise.reject(`string leaked ${marker}`),
    () => Promise.reject({ message: `object leaked ${marker}` }),
    () => Promise.reject(hostileProxy),
    () => new Proxy({}, {
      get: (_target, field) => {
        if (field === "then") throw new Error(`then getter leaked ${marker}`);
        return undefined;
      },
    }),
  ];
  for (const fetchImpl of attacks) {
    await assertStaticFailure(() => fetchGitHubJsonObserved(
      "https://api.github.com/example", installationToken, fetchImpl,
    ), marker, /API transport failed/);
  }
});

test("observed JSON transport rejects hostile content-length values without coercion", async () => {
  const marker = `content-length-marker-${installationToken}`;
  const lengths = [
    { toString() { throw new Error(`toString leaked ${marker}`); } },
    new Proxy({}, { get() { throw new Error(`proxy leaked ${marker}`); } }),
    Symbol(marker),
  ];
  for (const length of lengths) {
    const reader = { read: async () => ({ done: true, value: undefined }), cancel: async () => {} };
    await assertStaticFailure(() => fetchGitHubJsonObserved(
      "https://api.github.com/example",
      installationToken,
      async () => ({
        status: 200,
        ok: true,
        headers: { get: (name) => name === "date" ? "Thu, 13 Aug 2026 11:10:00 GMT" : length },
        body: { getReader: () => reader },
      }),
    ), marker, /invalid or too large/);
  }
  await assertStaticFailure(() => fetchGitHubJsonObserved(
    "https://api.github.com/example",
    installationToken,
    async () => ({
      status: 200,
      ok: true,
      headers: { get: (name) => {
        if (name === "date") return "Thu, 13 Aug 2026 11:10:00 GMT";
        throw new Error(`content-length getter leaked ${marker}`);
      } },
      body: null,
    }),
  ), marker, /primitives are invalid/);
});

test("observed JSON transport snapshots hostile stream results inside a static-error guard", async () => {
  const marker = `stream-result-marker-${installationToken}`;
  const hostileByteLength = new Uint8Array([1]);
  Object.defineProperty(hostileByteLength, "byteLength", {
    get() { throw new Error(`byteLength leaked ${marker}`); },
  });
  const hostileBufferCopy = new Proxy({}, {
    getPrototypeOf: () => Uint8Array.prototype,
    get: (_target, field) => {
      if (field === "byteLength") return 1;
      throw new Error(`Buffer conversion leaked ${marker}`);
    },
  });
  const results = [
    () => { throw new Error(`read leaked ${marker}`); },
    () => new Proxy({}, { get() { throw new Error(`result getter leaked ${marker}`); } }),
    () => ({ get done() { throw new Error(`done leaked ${marker}`); } }),
    () => ({ done: false, get value() { throw new Error(`value leaked ${marker}`); } }),
    () => ({ done: false, value: hostileByteLength }),
    () => ({ done: false, value: hostileBufferCopy }),
    () => ({ done: true, get value() { throw new Error(`terminal value leaked ${marker}`); } }),
  ];
  for (const result of results) {
    const reader = {
      read: async () => result(),
      cancel: async () => { throw new Error(`cancel leaked ${marker}`); },
    };
    await assertStaticFailure(() => fetchGitHubJsonObserved(
      "https://api.github.com/example",
      installationToken,
      async () => ({
        status: 200,
        ok: true,
        headers: { get: (name) => name === "date" ? "Thu, 13 Aug 2026 11:10:00 GMT" : null },
        body: { getReader: () => reader },
      }),
    ), marker, /body is invalid/);
  }
});

test("observed JSON transport rejects credential shapes before parsing without echo", async () => {
  const values = [
    { private_key: "example" },
    { value: "-----BEGIN PRIVATE KEY-----" },
    { value: `ghp_${"x".repeat(36)}` },
    { value: `ya29.${"x".repeat(30)}` },
    { value: `AIza${"x".repeat(35)}` },
  ];
  for (const value of values) {
    const body = JSON.stringify(value);
    let error;
    try {
      await fetchGitHubJsonObserved(
        "https://api.github.com/example", installationToken, async () => response(200, body),
      );
    } catch (caught) { error = caught; }
    assert.ok(error);
    assert.equal(error.message.includes(body), false);
  }
});

test("observed JSON transport enforces its actual streaming cap and cancels overflow", async () => {
  const exact = Buffer.from(`{"value":"${"x ".repeat(499_994)}"}`);
  assert.equal(exact.length, 1_000_000);
  const accepted = await fetchGitHubJsonObserved(
    "https://api.github.com/example", installationToken,
    async () => response(200, exact, { "content-length": String(exact.length) }),
  );
  assert.equal(accepted.value.value.length, 999_988);

  for (const declared of [undefined, "1"]) {
    let cancelled = false;
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(600_000));
        controller.enqueue(new Uint8Array(400_001));
      },
      cancel() { cancelled = true; },
    });
    const headers = { date: "Thu, 13 Aug 2026 11:10:00 GMT" };
    if (declared !== undefined) headers["content-length"] = declared;
    await assert.rejects(() => fetchGitHubJsonObserved(
      "https://api.github.com/example", installationToken,
      async () => new Response(body, { status: 200, headers }),
    ), /too large/);
    assert.equal(cancelled, true);
  }
  await assert.rejects(() => fetchGitHubJsonObserved(
    "https://api.github.com/example", installationToken,
    async () => response(200, {}, { "content-length": "1000001" }),
  ), /too large/);
});

test("observed download requires exactly one trusted, nonregressing redirect", async () => {
  const cases = [
    async () => response(200, "direct"),
    async () => response(302, "", { location: "https://objects.githubusercontent.com/file", date: "" }),
    async () => response(302, "", { location: "https://evil.example/file" }),
    async (url) => url.includes("api.github.com")
      ? response(302, "", { location: "https://objects.githubusercontent.com/file" })
      : response(200, "safe", { date: "" }),
    async (url) => url.includes("api.github.com")
      ? response(302, "", { location: "https://objects.githubusercontent.com/file" })
      : response(302, "", { location: "https://objects.githubusercontent.com/again" }),
    async (url) => url.includes("api.github.com")
      ? response(302, "", { location: "https://objects.githubusercontent.com/file", date: "Thu, 13 Aug 2026 11:11:00 GMT" })
      : response(200, "safe", { date: "Thu, 13 Aug 2026 11:10:00 GMT" }),
  ];
  for (const fetchImpl of cases) {
    await assert.rejects(() => downloadGitHubBytesObserved(
      "https://api.github.com/download", installationToken, fetchImpl, 100,
    ));
  }
});

test("observed download accepts only raw-safe established GitHub redirect host families", async () => {
  const accepted = [
    "https://objects.githubusercontent.com/file?sig=a%2Fb",
    "https://media.githubusercontent.com/file?sig=a%2Fb",
    "https://productionresultssa0.blob.core.windows.net/actions/results?sig=a%2Fb",
  ];
  for (const location of accepted) {
    const fetched = [];
    const result = await downloadGitHubBytesObserved(
      "https://api.github.com/download",
      installationToken,
      async (url) => {
        fetched.push(url);
        return url.includes("api.github.com")
          ? response(302, "", { location })
          : response(200, "evidence");
      },
      8,
    );
    assert.equal(result.bytes.toString(), "evidence");
    assert.deepEqual(fetched, ["https://api.github.com/download", location]);
  }

  const rejected = [
    "http://objects.githubusercontent.com/file",
    "https://objects.githubusercontent.com:443/file",
    "https://objects.githubusercontent.com:444/file",
    "https://user@objects.githubusercontent.com/file",
    "https://objects.githubusercontent.com@evil.example/file",
    "https://objects.githubusercontent.com\\@evil.example/file",
    "https://objects.githubusercontent.com%2e.evil.example/file",
    "https://objects.githubusercontent.com/file#fragment",
    "https://objects.githubusercontent.com.evil.example/file",
    "https://evilgithubusercontent.com/file",
    "https://blob.core.windows.net/file",
  ];
  for (const location of rejected) {
    let finalFetches = 0;
    await assert.rejects(() => downloadGitHubBytesObserved(
      "https://api.github.com/download",
      installationToken,
      async (url) => {
        if (!url.includes("api.github.com")) finalFetches += 1;
        return response(302, "", { location });
      },
      8,
    ), /not trusted/);
    assert.equal(finalFetches, 0);
  }
});

test("observed download replaces transport-controlled exception text with static errors", async () => {
  const marker = `signed-url-marker-${installationToken}`;

  await assertStaticFailure(() => downloadGitHubBytesObserved(
    "https://api.github.com/download",
    installationToken,
    async () => { throw new Error(`https://api.github.com/download?token=${marker}`); },
    100,
  ), marker, /initial transport failed/);

  await assertStaticFailure(() => downloadGitHubBytesObserved(
    "https://api.github.com/download",
    installationToken,
    async (url) => {
      if (url.includes("api.github.com")) {
        return response(302, "", {
          location: `https://productionresultssa0.blob.core.windows.net/result?sig=${marker}`,
        });
      }
      throw new Error(`SAS failure ${url} ${marker}`);
    },
    100,
  ), marker, /redirected transport failed/);

  await assertStaticFailure(() => downloadGitHubBytesObserved(
    "https://api.github.com/download",
    installationToken,
    async (url) => {
      if (url.includes("api.github.com")) {
        return response(302, "", { location: "https://objects.githubusercontent.com/result" });
      }
      return {
        status: 200,
        ok: true,
        headers: new Headers({ date: "Thu, 13 Aug 2026 11:10:00 GMT" }),
        body: { getReader: () => ({
          read: async () => { throw new Error(`reader leaked ${marker}`); },
          cancel: async () => { throw new Error(`cancel leaked ${marker}`); },
        }) },
      };
    },
    100,
  ), marker, /body is invalid/);

  await assertStaticFailure(() => downloadGitHubBytesObserved(
    "https://api.github.com/download",
    installationToken,
    async () => ({
      status: 302,
      get headers() { throw new Error(`header leaked ${marker}`); },
      body: null,
    }),
    100,
  ), marker, /redirect primitives are invalid/);

  await assertStaticFailure(() => downloadGitHubBytesObserved(
    "https://api.github.com/download",
    installationToken,
    async (url) => {
      if (url.includes("api.github.com")) {
        return response(302, "", { location: "https://objects.githubusercontent.com/result" });
      }
      return {
        status: 200,
        ok: true,
        get headers() { throw new Error(`final header leaked ${marker}`); },
        body: null,
      };
    },
    100,
  ), marker, /response primitives are invalid/);

  await assertStaticFailure(() => downloadGitHubBytesObserved(
    "https://api.github.com/download",
    installationToken,
    async () => ({
      status: 302,
      headers: new Headers({
        date: "Thu, 13 Aug 2026 11:10:00 GMT",
        location: "https://objects.githubusercontent.com/result",
      }),
      body: { cancel: async () => { throw new Error(`redirect cancel leaked ${marker}`); } },
    }),
    100,
  ), marker, /redirect body is invalid/);
});

test("observed download enforces the actual cap, cancels overflow, and does not disclose credentials", async () => {
  const exactFetch = async (url) => url.includes("api.github.com")
    ? response(302, "", { location: "https://objects.githubusercontent.com/file" })
    : response(200, "evidence");
  assert.equal((await downloadGitHubBytesObserved(
    "https://api.github.com/download", installationToken, exactFetch, 8,
  )).bytes.toString(), "evidence");

  for (const declared of [undefined, "1"]) {
    let cancelled = false;
    const fetchImpl = async (url) => {
      if (url.includes("api.github.com")) {
        return response(302, "", { location: "https://objects.githubusercontent.com/file" });
      }
      const body = new ReadableStream({
        start(controller) {
          controller.enqueue(Buffer.from("12345"));
          controller.enqueue(Buffer.from("6789"));
        },
        cancel() { cancelled = true; },
      });
      const responseHeaders = { date: "Thu, 13 Aug 2026 11:10:00 GMT" };
      if (declared !== undefined) responseHeaders["content-length"] = declared;
      return new Response(body, { status: 200, headers: responseHeaders });
    };
    await assert.rejects(() => downloadGitHubBytesObserved(
      "https://api.github.com/download", installationToken, fetchImpl, 8,
    ), /too large/);
    assert.equal(cancelled, true);
  }

  const secret = `ghp_${"x".repeat(36)}`;
  let error;
  try {
    await downloadGitHubBytesObserved(
      "https://api.github.com/download",
      installationToken,
      async (url) => url.includes("api.github.com")
        ? response(302, "", { location: "https://objects.githubusercontent.com/file" })
        : response(200, secret),
      100,
    );
  } catch (caught) { error = caught; }
  assert.ok(error);
  assert.equal(error.message.includes(secret), false);
});

test("observed JSON transport snapshots response primitives before reading the body", async () => {
  const responseHeaders = new Headers({ date: "Thu, 13 Aug 2026 11:10:00 GMT" });
  let status = 200;
  let bodyReads = 0;
  let reads = 0;
  const body = { getReader: () => ({
    read: async () => {
      reads += 1;
      status = 500;
      responseHeaders.set("date", "invalid-after-capture");
      return reads === 1
        ? { done: false, value: Buffer.from('{"safe":true}') }
        : { done: true, value: undefined };
    },
    cancel: async () => {},
  }) };
  const mutableResponse = {
    get status() { return status; },
    get ok() { return status === 200; },
    headers: responseHeaders,
    get body() {
      bodyReads += 1;
      if (bodyReads > 1) throw new Error("body was reread");
      return body;
    },
  };
  assert.deepEqual(await fetchGitHubJsonObserved(
    "https://api.github.com/example", installationToken, async () => mutableResponse,
  ), { value: { safe: true }, observedAt: "2026-08-13T11:10:00Z" });
  assert.equal(bodyReads, 1);
});

test("collectors reject response time earlier than the authoritative job event", async () => {
  const { fetchImpl } = fixture();
  await assert.rejects(() => collectGitHubDenialEvidence({
    ...input,
    fetchImpl: async (url, options) => {
      const reply = await fetchImpl(url, options);
      if (url.includes("/contents/demo/release.txt")) {
        return new Response(await reply.arrayBuffer(), {
          status: reply.status,
          headers: { date: "Thu, 13 Aug 2026 11:00:00 GMT" },
        });
      }
      return reply;
    },
  }), /after collection/);

  const redirectAttack = fixture();
  await assert.rejects(() => collectGitHubDenialEvidence({
    ...input,
    fetchImpl: async (url, options) => {
      const reply = await redirectAttack.fetchImpl(url, options);
      if (!url.endsWith("/actions/jobs/77/logs")) return reply;
      const headers = Object.fromEntries(reply.headers.entries());
      headers.date = "Thu, 13 Aug 2026 11:00:00 GMT";
      return new Response(await reply.arrayBuffer(), { status: reply.status, headers });
    },
  }), /download response/);
});
