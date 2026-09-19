/**
 * The HTML report.
 *
 * Self-contained on purpose: no stylesheet, no script and no image is fetched over the network,
 * because the thing this report most often has to survive is being emailed, attached to an issue,
 * or opened from a `file://` path six months later. Screenshots are inlined as data URIs and logs
 * are inlined as text, so `e2e/report/index.html` is one file you can move anywhere.
 */

import fs from "node:fs";
import path from "node:path";

const MIME = {
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
};

/** Cap on how much of a log file is embedded, in bytes. The tail is what matters after a failure. */
const LOG_TAIL_BYTES = 16 * 1024;

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function dataUri(file) {
  const mime = MIME[path.extname(file).toLowerCase()];
  if (!mime) return null;
  return `data:${mime};base64,${fs.readFileSync(file).toString("base64")}`;
}

function tail(file) {
  const size = fs.statSync(file).size;
  if (size <= LOG_TAIL_BYTES) return fs.readFileSync(file, "utf8");
  const handle = fs.openSync(file, "r");
  try {
    const buffer = Buffer.alloc(LOG_TAIL_BYTES);
    fs.readSync(handle, buffer, 0, LOG_TAIL_BYTES, size - LOG_TAIL_BYTES);
    return `… ${size - LOG_TAIL_BYTES} earlier bytes omitted …\n${buffer.toString("utf8")}`;
  } finally {
    fs.closeSync(handle);
  }
}

function duration(seconds) {
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} m ${Math.round(seconds - minutes * 60)} s`;
}

function renderArtifacts(artifacts) {
  if (!artifacts || artifacts.length === 0) return "";
  const parts = [];
  for (const item of artifacts) {
    if (!fs.existsSync(item.path)) continue;
    if (item.kind === "image") {
      const uri = dataUri(item.path);
      if (!uri) continue;
      parts.push(
        `<figure><img src="${uri}" alt="${escapeHtml(item.label)}">` +
          `<figcaption>${escapeHtml(item.label)}</figcaption></figure>`,
      );
    } else {
      parts.push(
        `<div class="log"><div class="log-label">${escapeHtml(item.label)}</div>` +
          `<pre>${escapeHtml(tail(item.path))}</pre></div>`,
      );
    }
  }
  if (parts.length === 0) return "";
  return `<details class="artifacts"><summary>${parts.length} artifact(s)</summary>
      <div class="artifact-body">${parts.join("\n")}</div></details>`;
}

function renderCase(testcase) {
  const pill = `<span class="pill ${testcase.status}">${testcase.status}</span>`;
  const failure =
    testcase.status === "failed"
      ? `<pre class="failure">${escapeHtml(testcase.detail || testcase.message)}</pre>`
      : "";
  const skipReason =
    testcase.status === "skipped" && testcase.message
      ? `<div class="reason">${escapeHtml(testcase.message)}</div>`
      : "";
  return `<div class="case ${testcase.status}">
      <div class="case-head">
        ${pill}
        <span class="case-name">${escapeHtml(testcase.name)}</span>
        <span class="case-time">${duration(testcase.seconds)}</span>
      </div>
      ${skipReason}
      ${failure}
      ${renderArtifacts(testcase.artifacts)}
    </div>`;
}

function renderSuite(suite) {
  const counts = {
    passed: suite.cases.filter((c) => c.status === "passed").length,
    failed: suite.cases.filter((c) => c.status === "failed").length,
    skipped: suite.cases.filter((c) => c.status === "skipped").length,
  };
  const state = suite.cases.some((c) => c.status === "failed")
    ? "failed"
    : suite.cases.length === 0
      ? "skipped"
      : "passed";
  const note = suite.note ? `<p class="note">${escapeHtml(suite.note)}</p>` : "";
  const body =
    suite.cases.length > 0
      ? suite.cases.map(renderCase).join("\n")
      : `<div class="case skipped"><div class="case-head">
           <span class="pill skipped">no scenarios</span>
           <span class="case-name">This suite produced no JUnit results.</span></div></div>`;
  return `<section class="suite ${state}">
      <h2>${escapeHtml(suite.title || suite.name)}
        <span class="counts">${counts.passed} passed · ${counts.failed} failed ·
          ${counts.skipped} skipped · ${duration(suite.seconds)}</span>
      </h2>
      ${suite.description ? `<p class="desc">${escapeHtml(suite.description)}</p>` : ""}
      ${note}
      ${body}
    </section>`;
}

const STYLE = `
  :root { color-scheme: light dark; --bg:#fbfbfa; --fg:#1c1c1e; --muted:#6b6b70;
          --line:#e2e2df; --card:#ffffff; --pass:#1f7a3d; --fail:#b3261e; --skip:#8a6d11;
          --passbg:#e8f5ec; --failbg:#fdeceb; --skipbg:#fdf4dd; --mono:ui-monospace,
          SFMono-Regular, "SF Mono", Menlo, monospace; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#151517; --fg:#ececed; --muted:#9a9aa0; --line:#2e2e33; --card:#1d1d20;
            --pass:#6ede90; --fail:#ff8a80; --skip:#f0cf6a;
            --passbg:#153021; --failbg:#3a1a18; --skipbg:#332a10; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:14px/1.5 -apple-system,
         BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; }
  .wrap { max-width: 1040px; margin: 0 auto; padding: 32px 20px 80px; }
  h1 { font-size: 24px; margin: 0 0 4px; letter-spacing: -0.01em; }
  .sub { color: var(--muted); margin: 0 0 28px; }
  .verdict { display:inline-block; padding:4px 12px; border-radius:999px; font-weight:650;
             font-size:13px; letter-spacing:0.02em; text-transform:uppercase; }
  .verdict.passed { background:var(--passbg); color:var(--pass); }
  .verdict.failed { background:var(--failbg); color:var(--fail); }
  .summary { display:flex; gap:10px; flex-wrap:wrap; margin: 0 0 28px; }
  .stat { background:var(--card); border:1px solid var(--line); border-radius:10px;
          padding:10px 16px; min-width:104px; }
  .stat b { display:block; font-size:22px; line-height:1.2; }
  .stat span { color:var(--muted); font-size:12px; }
  .stat.failed b { color: var(--fail); }
  .env { background:var(--card); border:1px solid var(--line); border-radius:10px;
         padding:4px 16px 14px; margin-bottom:28px; }
  .env h2 { font-size:13px; text-transform:uppercase; letter-spacing:0.06em;
            color:var(--muted); margin:16px 0 6px; }
  .env table { border-collapse:collapse; width:100%; }
  .env td { padding:2px 0; vertical-align:top; }
  .env td:first-child { color:var(--muted); width:180px; padding-right:16px; }
  .env td:last-child { font-family:var(--mono); font-size:12.5px; word-break:break-word; }
  section.suite { background:var(--card); border:1px solid var(--line); border-radius:10px;
                  padding:16px 18px; margin-bottom:20px; }
  section.suite h2 { font-size:17px; margin:0 0 2px; display:flex; flex-wrap:wrap;
                     align-items:baseline; gap:10px; }
  .counts { font-size:12.5px; font-weight:400; color:var(--muted); }
  .desc, .note { color:var(--muted); margin:0 0 12px; font-size:13px; }
  .note { border-left:3px solid var(--line); padding-left:10px; }
  .case { border-top:1px solid var(--line); padding:9px 0; }
  .case-head { display:flex; align-items:baseline; gap:10px; }
  .case-name { flex:1; }
  .case.failed .case-name { color: var(--fail); font-weight:600; }
  .case-time { color:var(--muted); font-size:12px; font-variant-numeric:tabular-nums; }
  .pill { font-size:10.5px; font-weight:700; letter-spacing:0.05em; text-transform:uppercase;
          padding:2px 8px; border-radius:999px; min-width:62px; text-align:center; }
  .pill.passed { background:var(--passbg); color:var(--pass); }
  .pill.failed { background:var(--failbg); color:var(--fail); }
  .pill.skipped { background:var(--skipbg); color:var(--skip); }
  .reason { color:var(--muted); margin:4px 0 0 72px; font-size:13px; white-space:pre-wrap; }
  pre { font-family:var(--mono); font-size:12px; overflow-x:auto; background:var(--bg);
        border:1px solid var(--line); border-radius:6px; padding:10px; margin:8px 0 0; }
  pre.failure { color:var(--fail); border-color:var(--fail); background:var(--failbg);
                white-space:pre-wrap; }
  details.artifacts { margin:8px 0 0 72px; }
  details.artifacts summary { cursor:pointer; color:var(--muted); font-size:12.5px; }
  .artifact-body { display:flex; flex-direction:column; gap:14px; margin-top:10px; }
  figure { margin:0; }
  figure img { max-width:100%; border:1px solid var(--line); border-radius:6px; display:block; }
  figcaption { color:var(--muted); font-size:12px; margin-top:4px; }
  .log-label { color:var(--muted); font-size:12px; }
  footer { color:var(--muted); font-size:12px; margin-top:40px; }
`;

/**
 * Render the whole report.
 *
 * @param {{ suites: object[], environment: object[], seconds: number, command: string }} run
 */
export function renderReport(run) {
  const all = run.suites.flatMap((s) => s.cases);
  const totals = {
    passed: all.filter((c) => c.status === "passed").length,
    failed: all.filter((c) => c.status === "failed").length,
    skipped: all.filter((c) => c.status === "skipped").length,
  };
  const verdict = totals.failed > 0 ? "failed" : "passed";

  const env = run.environment
    .map(
      (group) =>
        `<h2>${escapeHtml(group.group)}</h2><table>${group.rows
          .map(
            ([k, v]) =>
              `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(v ?? "unknown")}</td></tr>`,
          )
          .join("")}</table>`,
    )
    .join("\n");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kagisecure end-to-end report</title>
<style>${STYLE}</style>
</head>
<body>
<div class="wrap">
  <h1>kagisecure end-to-end report</h1>
  <p class="sub">
    <span class="verdict ${verdict}">${verdict}</span>
    &nbsp;${escapeHtml(run.command)} · ${duration(run.seconds)}
  </p>

  <div class="summary">
    <div class="stat"><b>${all.length}</b><span>scenarios</span></div>
    <div class="stat"><b>${totals.passed}</b><span>passed</span></div>
    <div class="stat ${totals.failed ? "failed" : ""}"><b>${totals.failed}</b><span>failed</span></div>
    <div class="stat"><b>${totals.skipped}</b><span>skipped</span></div>
    <div class="stat"><b>${run.suites.length}</b><span>suites</span></div>
  </div>

  <div class="env">${env}</div>

  ${run.suites.map(renderSuite).join("\n")}

  <footer>
    Generated by <code>e2e/run.mjs</code>. Screenshots and logs are embedded, so this file stands
    on its own. The machine-readable form of the same run is <code>junit.xml</code> beside it.
  </footer>
</div>
</body>
</html>
`;
}
