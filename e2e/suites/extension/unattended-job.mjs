/**
 * The job of the unattended sign-in scenario (ADR-0042 §12): what a scheduled agent does.
 *
 * kagisecure starts this as the run's root, with `KAGISECURE_SOCKET` naming the unattended socket
 * and `KAGISECURE_RUN_BROWSER_CDP` naming the run browser's control endpoint. It drives that
 * browser to the sign-in page, asks its own `kagisecure-mcp` for `request_fill`, submits the form,
 * writes what it saw to the result file — never a value: it has none — and waits for the test to
 * release it, so the run (and its browser's extension endpoint) is still up while the test tries
 * another browser against that endpoint.
 *
 * Usage: node unattended-job.mjs <result file> <release file> <origin> <item id>
 */

import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

import { REPO_ROOT, Sidecar } from "../../lib/harness.mjs";

const [resultFile, releaseFile, origin, itemId] = process.argv.slice(2);
const require = createRequire(path.join(REPO_ROOT, "extensions", "chrome", "package.json"));
const { chromium } = require("playwright");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const out = { attempts: [] };

try {
  const browser = await chromium.connectOverCDP(process.env.KAGISECURE_RUN_BROWSER_CDP);
  const context = browser.contexts()[0];
  const page = context.pages()[0] ?? (await context.newPage());
  await page.goto(`${origin}/unattended-login.html`);
  await page.focus("#username");

  const sidecar = new Sidecar(process.env.KAGISECURE_SOCKET, {
    cwd: process.cwd(),
    clientName: "unattended-job",
  });
  await sidecar.initialize();
  // The extension says hello when the page first asks it something; until then the run's browser
  // is not connected, and the answer is FILL_UNAVAILABLE, which is not a strike.
  let result;
  for (let i = 0; i < 30; i++) {
    result = await sidecar.call(
      "request_fill",
      { item_id: itemId, origin, fields: ["username", "password"] },
      { timeoutMs: 120_000 },
    );
    out.attempts.push({ ok: result.ok, text: result.text });
    if (result.ok || !/FILL_UNAVAILABLE|NO_MATCHING_TAB/.test(JSON.stringify(result.raw))) break;
    await sleep(1000);
    await page.focus("#username").catch(() => {});
  }
  out.fill = { ok: result.ok, text: result.text, structured: result.structured };
  out.sidecarStdout = sidecar.rawStdout;
  out.sidecarStderr = sidecar.rawStderr;
  out.visibility = await page.evaluate(() => document.visibilityState);
  if (result.ok) {
    await page.screenshot({ path: path.join(path.dirname(resultFile), "unattended-filled.png") });
    await Promise.all([page.waitForURL(/signed-in/), page.click("button[type=submit]")]);
    out.after = await page.textContent("body");
  }
  sidecar.stop();
} catch (e) {
  out.error = String(e && e.stack ? e.stack : e);
}

fs.writeFileSync(resultFile, JSON.stringify(out, null, 2));
const deadline = Date.now() + 120_000;
while (!fs.existsSync(releaseFile) && Date.now() < deadline) await sleep(200);
process.exit(0);
