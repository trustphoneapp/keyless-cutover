import { createServer } from "node:http";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { getUntamperedConsoleStatusSnapshot, loadConsoleStatus } from "./status.mjs";

const STATUS_FIELDS = new Set([
  "version", "status", "authorization", "release_ready", "cutover_verified", "signature_verified",
  "eyebrow", "headline", "summary", "recorded_at", "checkpoint_sha256", "metrics", "gates",
  "blockers", "sources", "limitations",
]);

const SECURITY_HEADERS = {
  "cache-control": "no-store",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
};

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

function renderGate(item, index) {
  return `<li class="gate gate--${escapeHtml(item.state)}">
    <span class="gate__index">${String(index + 1).padStart(2, "0")}</span>
    <span><strong>${escapeHtml(item.label)}</strong><small>${escapeHtml(item.detail)}</small></span>
    <span class="gate__state">${escapeHtml(item.state)}</span>
  </li>`;
}

export function renderConsoleHtml(status) {
  const badge = status.status === "K0_VERIFIED_RECEIPT_PENDING"
    ? status.signature_verified ? "Signature verified · recollection required" : "Bundle verified · recollection required"
    : status.status === "NO_GO_VERIFICATION_FAILED" ? "No-go · verification failed" : "No-go · evidence incomplete";
  const metricCards = status.metrics.map((item) => `<div class="metric"><strong>${escapeHtml(item.value)}</strong><span>${escapeHtml(item.label)}</span></div>`).join("");
  const sources = status.sources.length
    ? status.sources.map((item) => `<a href="${escapeHtml(item.href)}" rel="noopener noreferrer">${escapeHtml(item.label)}<span>↗</span></a>`).join("")
    : "<p>No public evidence source is eligible.</p>";
  const hashLabel = status.status === "K0_VERIFIED_RECEIPT_PENDING" ? "Manifest SHA-256" : "Checkpoint SHA-256";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Keyless Cutover evidence console — a fail-closed proof of GitHub Actions to Google Workload Identity Federation migration.">
  <title>Keyless Cutover · Evidence Console</title>
  <style>
    :root { color-scheme: dark; --ink:#07110f; --panel:#0d1b18; --line:#25413a; --mint:#83f6bd; --amber:#ffd37a; --muted:#9eb7af; --paper:#eff8f2; }
    * { box-sizing:border-box; }
    body { margin:0; background:radial-gradient(circle at 78% 4%,#1a493b 0,transparent 32%),linear-gradient(145deg,#06100e,#0b1d18 55%,#08120f); color:var(--paper); font:16px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    body:before { content:""; position:fixed; inset:0; pointer-events:none; opacity:.18; background-image:linear-gradient(rgba(255,255,255,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.04) 1px,transparent 1px); background-size:48px 48px; }
    main { position:relative; max-width:1180px; margin:auto; padding:28px 24px 72px; }
    nav { display:flex; justify-content:space-between; align-items:center; padding:8px 0 72px; }
    .brand { letter-spacing:.16em; text-transform:uppercase; font-weight:800; }
    .brand span { color:var(--mint); }
    .badge { border:1px solid var(--amber); color:var(--amber); padding:7px 12px; border-radius:999px; font-size:.76rem; font-weight:800; letter-spacing:.08em; text-transform:uppercase; }
    .hero { display:grid; grid-template-columns:minmax(0,1.45fr) minmax(280px,.55fr); gap:52px; align-items:end; padding-bottom:64px; }
    .eyebrow { color:var(--mint); letter-spacing:.15em; text-transform:uppercase; font-size:.78rem; font-weight:800; }
    h1 { font-size:clamp(3.1rem,8vw,7.2rem); line-height:.86; letter-spacing:-.065em; max-width:850px; margin:18px 0 30px; }
    .summary { max-width:720px; color:#c0d2cc; font-size:1.12rem; }
    .contract { border-left:2px solid var(--mint); padding:4px 0 4px 22px; color:var(--muted); }
    .contract strong { display:block; color:var(--paper); font-size:1.15rem; margin-bottom:8px; }
    .metrics { display:grid; grid-template-columns:repeat(4,1fr); gap:1px; background:var(--line); border:1px solid var(--line); margin-bottom:54px; }
    .metric { background:rgba(8,24,20,.92); padding:25px; min-height:116px; }
    .metric strong { display:block; color:var(--mint); font-size:2rem; letter-spacing:-.04em; }
    .metric span { color:var(--muted); font-size:.82rem; text-transform:uppercase; letter-spacing:.07em; }
    .grid { display:grid; grid-template-columns:1.45fr .75fr; gap:28px; }
    .panel { background:rgba(13,27,24,.86); border:1px solid var(--line); padding:30px; backdrop-filter:blur(12px); }
    .panel h2 { margin:0 0 24px; font-size:1.4rem; }
    .panel__kicker { color:var(--muted); font-size:.76rem; letter-spacing:.11em; text-transform:uppercase; margin-bottom:7px; }
    .gates { list-style:none; padding:0; margin:0; }
    .gate { display:grid; grid-template-columns:38px 1fr auto; gap:14px; align-items:center; padding:15px 0; border-top:1px solid var(--line); }
    .gate__index { color:#5f7d73; font:700 .72rem ui-monospace,SFMono-Regular,Menlo,monospace; }
    .gate strong,.gate small { display:block; }
    .gate small { color:var(--muted); margin-top:2px; }
    .gate__state { text-transform:uppercase; letter-spacing:.08em; font-size:.7rem; font-weight:900; color:var(--amber); }
    .gate--passed .gate__state,.gate--observed .gate__state,.gate--denied .gate__state { color:var(--mint); }
    .side { display:grid; gap:28px; align-content:start; }
    .blockers { margin:0; padding-left:20px; color:#d6e2de; }
    .blockers li { margin:0 0 12px; }
    .sources { display:grid; gap:10px; }
    .sources a { display:flex; justify-content:space-between; gap:20px; color:var(--paper); text-decoration:none; padding:12px 0; border-top:1px solid var(--line); }
    .sources a:hover,.sources a:focus-visible { color:var(--mint); }
    .hash { color:#86a198; font:600 .72rem/1.6 ui-monospace,SFMono-Regular,Menlo,monospace; overflow-wrap:anywhere; margin-top:28px; }
    footer { border-top:1px solid var(--line); margin-top:48px; padding-top:26px; display:flex; justify-content:space-between; gap:30px; color:var(--muted); font-size:.82rem; }
    @media (max-width:800px) { nav{padding-bottom:46px}.hero,.grid{grid-template-columns:1fr}.hero{gap:28px}.metrics{grid-template-columns:repeat(2,1fr)}h1{font-size:clamp(3.2rem,16vw,5.6rem)} }
    @media (max-width:480px) { main{padding:20px 16px 48px}.badge{font-size:.62rem}.metrics{grid-template-columns:1fr 1fr}.metric{padding:18px}.panel{padding:22px}.gate{grid-template-columns:28px 1fr}.gate__state{grid-column:2}footer{display:block} }
  </style>
</head>
<body>
  <main>
    <nav><div class="brand">Keyless<span> / Evidence</span></div><div class="badge">${escapeHtml(badge)}</div></nav>
    <section class="hero">
      <div><div class="eyebrow">${escapeHtml(status.eyebrow)}</div><h1>${escapeHtml(status.headline)}</h1><p class="summary">${escapeHtml(status.summary)}</p></div>
      <div class="contract"><strong>Gemini interprets.</strong>Deterministic code proves. Humans authorize. Missing evidence stops the workflow.</div>
    </section>
    <section class="metrics" aria-label="Evaluation metrics">${metricCards}</section>
    <section class="grid">
      <div class="panel"><div class="panel__kicker">Authoritative sequence</div><h2>Cutover gates</h2><ol class="gates">${status.gates.map(renderGate).join("")}</ol></div>
      <div class="side">
        <section class="panel"><div class="panel__kicker">Fail-closed state</div><h2>What still blocks release</h2><ul class="blockers">${status.blockers.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></section>
        <section class="panel"><div class="panel__kicker">Reconstructable proof</div><h2>External sources</h2><div class="sources">${sources}</div>${status.checkpoint_sha256 ? `<div class="hash">${hashLabel}<br>${escapeHtml(status.checkpoint_sha256)}</div>` : ""}</section>
      </div>
    </section>
    <footer><span>Scoped to one GitHub Actions workflow, one GCP service account, and one Cloud Run target.</span><span>${status.recorded_at ? `Observed ${escapeHtml(status.recorded_at)}` : "Verification stopped"}</span></footer>
  </main>
</body>
</html>`;
}

function send(response, statusCode, contentType, body) {
  response.writeHead(statusCode, { ...SECURITY_HEADERS, "content-type": contentType, "content-length": Buffer.byteLength(body) });
  response.end(body);
}

function exactStatusFields(status) {
  const keys = Reflect.ownKeys(status);
  return Object.getPrototypeOf(status) === Object.prototype
    && keys.length === STATUS_FIELDS.size
    && keys.every((key) => typeof key === "string" && STATUS_FIELDS.has(key));
}

function validStateTuple(status) {
  if (status.version !== 1 || status.release_ready !== false || status.cutover_verified !== false) return false;
  if (status.status === "NO_GO_INCOMPLETE") {
    return status.authorization === "INCOMPLETE" && status.signature_verified === false;
  }
  if (status.status === "NO_GO_VERIFICATION_FAILED") {
    return status.authorization === "VERIFICATION_FAILED" && status.signature_verified === false;
  }
  return status.status === "K0_VERIFIED_RECEIPT_PENDING"
    && status.authorization === "RECOLLECTION_REQUIRED"
    && typeof status.signature_verified === "boolean";
}

export function createConsoleServer(status) {
  let capturedStatus;
  try {
    capturedStatus = getUntamperedConsoleStatusSnapshot(status);
  } catch {
    throw new Error("console status is not fail-closed");
  }
  if (!exactStatusFields(capturedStatus) || !validStateTuple(capturedStatus)) {
    throw new Error("console status is not fail-closed");
  }
  return createServer((request, response) => {
    if (request.method === "GET" && request.url === "/healthz") {
      response.writeHead(204, SECURITY_HEADERS);
      response.end();
      return;
    }
    if (request.method === "GET" && request.url === "/api/status") {
      send(response, 200, "application/json; charset=utf-8", `${JSON.stringify(capturedStatus)}\n`);
      return;
    }
    if (request.method === "GET" && request.url === "/") {
      send(response, 200, "text/html; charset=utf-8", renderConsoleHtml(capturedStatus));
      return;
    }
    send(response, 404, "application/json; charset=utf-8", '{"error":"not_found"}\n');
  });
}

async function main() {
  const port = Number(process.env.PORT ?? 8080);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("PORT is invalid");
  const status = await loadConsoleStatus({
    checkpointPath: process.env.KEYLESS_CHECKPOINT_PATH ?? "docs/evidence/K0_CHECKPOINT_2026-08-13.json",
    bundlePath: process.env.KEYLESS_K0_BUNDLE_PATH,
    manifestPath: process.env.KEYLESS_K0_MANIFEST_PATH,
  });
  createConsoleServer(status).listen(port, "0.0.0.0", () => process.stdout.write(`keyless-console listening on ${port}\n`));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
