/**
 * Suite B — unattended sign-ins (ADR-0042 §12), headless only.
 *
 * ```text
 *   unattended_harness ── starts ──▶ run browser (--headless=new, fresh profile, the extension)
 *        │                                  │ native messaging
 *        │                                  ▼
 *        │                           kagisecure-nmhost ──▶ the run's extension endpoint
 *        └── starts ──▶ the job (node) ── CDP ──▶ run browser
 *                          └── stdio ──▶ kagisecure-mcp ──▶ the unattended socket
 * ```
 *
 * Real here: the engine, the machine vault, the login grant, the run browser the engine starts,
 * the extension it loads, the native host that browser launches, the ancestry gate on the run's
 * extension endpoint, the job's own sidecar, the broker and the audited release. Not real: the
 * person, who created the grant in the app — the harness writes it.
 *
 * Nothing here opens a window or takes focus: the run browser and the other browser are both new
 * headless (`--headless=new`), which loads an MV3 extension and reads a profile's native messaging
 * manifest in Chromium and Microsoft Edge (ADR-0042 implementation decision 40). The page server is
 * https with a certificate made for the run, since a login grant names an exact https origin; the
 * browsers are told to accept it and to resolve every host to 127.0.0.1.
 *
 * The two scenarios the ADR keeps as the key tests:
 *
 * - **a canary with a successful unattended fill**: the password reaches the page's form post,
 *   and no tool result, sidecar byte, harness byte or audit entry;
 * - **a session from a browser other than the run's is refused**: a second browser, pointed at
 *   the run's own extension endpoint, is turned away before it can say anything.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createRequire } from "node:module";

import { REPO_ROOT, binary, exampleBinary, scratch, waitFor, canary } from "../../lib/harness.mjs";
import { artifactDir, record, recordText } from "../../lib/artifacts.mjs";

const EXTENSION_DIR = path.join(REPO_ROOT, "extensions", "shared");
const PAGES = path.join(import.meta.dirname, "pages");
const JOB = path.join(import.meta.dirname, "unattended-job.mjs");
const EXTENSION_ID = "nlijibjnmanccalmafnfbobkcfjiibmd";
const HOST_NAME = "com.kagisecure.nmhost";
const USERNAME = "service-bot@example.test";

function loadPlaywright() {
  const require = createRequire(path.join(REPO_ROOT, "extensions", "chrome", "package.json"));
  return require("playwright");
}

/** A browser that loads the extension headless: Playwright's Chromium, else Microsoft Edge. */
function runBrowserPath(chromium) {
  const candidates = [];
  try {
    candidates.push(chromium.executablePath());
  } catch {
    /* not installed */
  }
  candidates.push("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge");
  return candidates.find((p) => p && !p.includes("headless_shell") && fs.existsSync(p)) ?? null;
}

/** A certificate for this run, from the system `openssl`, or null. */
function certificate(dir) {
  const key = path.join(dir, "key.pem");
  const cert = path.join(dir, "cert.pem");
  const made = spawnSync(
    "openssl",
    ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1",
     "-subj", "/CN=app.example.com"],
    { stdio: "ignore" },
  );
  if (made.status !== 0) return null;
  return { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
}

/** Serve `pages/` over https, and record each sign-in form post. */
function servePages(tls) {
  const posts = [];
  const server = https.createServer(tls, (req, res) => {
    if (req.method === "POST" && req.url === "/signed-in") {
      let body = "";
      req.setEncoding("utf8");
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        posts.push(Object.fromEntries(new URLSearchParams(body)));
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(
          "<!doctype html><title>Signed in</title><p>Signed in.</p>",
        );
      });
      return;
    }
    const name = (req.url || "/").split("?")[0].replace(/^\//, "") || "unattended-login.html";
    const file = path.resolve(PAGES, name);
    if (!file.startsWith(PAGES + path.sep)) {
      res.writeHead(404).end("not found");
      return;
    }
    fs.readFile(file, (err, body) => {
      if (err) {
        res.writeHead(404).end("not found");
        return;
      }
      const type = file.endsWith(".css") ? "text/css" : "text/html";
      res.writeHead(200, { "content-type": `${type}; charset=utf-8` }).end(body);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port, posts }));
  });
}

function installManifest(profileDir) {
  const file = path.join(profileDir, "NativeMessagingHosts", `${HOST_NAME}.json`);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(
    file,
    JSON.stringify({
      name: HOST_NAME,
      description: "kagisecure autofill bridge",
      path: binary("kagisecure-nmhost"),
      type: "stdio",
      allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
    }),
  );
}

const BROWSER_ARGS = ["--ignore-certificate-errors", "--host-resolver-rules=MAP * 127.0.0.1"];

const SCENARIO = "unattended sign-in: a canary fill in the run's browser, and another browser refused";

test(SCENARIO, async (t) => {
  const { chromium } = loadPlaywright();
  const browserPath = runBrowserPath(chromium);
  if (!browserPath) {
    t.skip("no Chromium-family browser that loads an unpacked extension headless");
    return;
  }
  const dir = scratch(`unattended-${process.pid}`);
  const tls = certificate(dir);
  if (!tls) {
    t.skip("openssl could not make a certificate");
    return;
  }
  const password = canary("KSE2E-UNATTENDED");
  const { server, port, posts } = await servePages(tls);
  t.after(() => server.close());
  const origin = `https://app.example.com:${port}`;
  const resultFile = path.join(dir, "job-result.json");
  const releaseFile = path.join(dir, "job-release");

  const args = [
    "--dir", dir,
    "--browser", browserPath,
    "--origin", origin,
    "--username", USERNAME,
    "--password", password,
    "--nmhost", binary("kagisecure-nmhost"),
    "--extension", EXTENSION_DIR,
    "--job", process.execPath,
    "--job-arg", JOB,
    "--job-arg", resultFile,
    "--job-arg", releaseFile,
    "--job-arg", origin,
  ];
  for (const a of BROWSER_ARGS) args.push("--browser-arg", a);
  const harness = spawn(exampleBinary("unattended_harness"), args, { stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  harness.stdout.setEncoding("utf8").on("data", (c) => (stdout += c));
  harness.stderr.setEncoding("utf8").on("data", (c) => (stderr += c));
  t.after(() => harness.kill("SIGTERM"));
  const exited = new Promise((resolve) => harness.on("exit", resolve));

  await waitFor(() => stdout.includes("ready "), { timeoutMs: 60_000, what: "the harness to start the job" });
  await waitFor(() => fs.existsSync(resultFile), { timeoutMs: 240_000, what: "the job to sign in" });
  const job = JSON.parse(fs.readFileSync(resultFile, "utf8"));
  recordText(SCENARIO, "unattended-job.json", JSON.stringify({ ...job, sidecarStdout: undefined }, null, 2));

  // Another browser, pointed at the run's own extension endpoint: refused.
  const socket = fs
    .readdirSync(dir)
    .filter((n) => n.startsWith("ux-") && n.endsWith(".sock"))
    .map((n) => path.join(dir, n))[0];
  assert.ok(socket, "the run's extension endpoint exists while the run lasts");
  const otherProfile = path.join(dir, "other-profile");
  installManifest(otherProfile);
  const other = await chromium.launchPersistentContext(otherProfile, {
    executablePath: browserPath,
    headless: true,
    args: [
      "--headless=new",
      `--disable-extensions-except=${EXTENSION_DIR}`,
      `--load-extension=${EXTENSION_DIR}`,
      "--no-first-run",
      "--no-default-browser-check",
      ...BROWSER_ARGS,
    ],
    env: { ...process.env, KAGISECURE_EXTENSION_SOCKET: socket },
    timeout: 60_000,
  });
  try {
    const page = await other.newPage();
    await page.goto(`${origin}/unattended-login.html`);
    await page.focus("#username");
    await page.waitForTimeout(4000);
  } finally {
    await other.close().catch(() => {});
  }

  fs.writeFileSync(releaseFile, "");
  let timer;
  await Promise.race([exited, new Promise((r) => (timer = setTimeout(r, 120_000)))]);
  clearTimeout(timer);
  const outcome = JSON.parse(fs.readFileSync(path.join(dir, "outcome.json"), "utf8"));
  recordText(SCENARIO, "unattended-outcome.json", JSON.stringify(outcome, null, 2));
  const shot = path.join(dir, "unattended-filled.png");
  if (artifactDir() && fs.existsSync(shot)) {
    const kept = path.join(artifactDir(), "unattended-filled.png");
    fs.copyFileSync(shot, kept);
    record(SCENARIO, kept, { label: "The run browser's page after the unattended fill", kind: "image" });
  }

  // The fill happened: the page's own form post carried the canary.
  assert.ok(!job.error, `the job failed: ${job.error}`);
  assert.equal(job.fill?.ok, true, `request_fill: ${JSON.stringify(job.attempts)}`);
  assert.equal(posts.length, 1, `one sign-in reached the site: ${posts.length}`);
  assert.equal(posts[0].username, USERNAME);
  assert.equal(posts[0].password, password, "the password the site received is the vault's");

  // Audited as an unattended fill under the grant, at the exact origin.
  const fills = outcome.entries.filter((e) => e.tool === "request_fill");
  const approved = fills.find((e) => (e.detail || "").startsWith("UNATTENDED_FILL_APPROVED (grant "));
  assert.ok(approved, JSON.stringify(outcome.entries, null, 2));
  assert.equal(approved.outcome, "Allowed");
  assert.equal(approved.target, origin);
  assert.match(approved.actor, /^mcp unattended "sign in" run 1 pid \d+ /);
  assert.deepEqual(outcome.login_grants, [{ uses: 1, suspended: null }]);

  // The other browser was turned away and recorded; no grant was suspended for it.
  assert.ok(
    outcome.entries.some((e) => e.detail === "HOST_REFUSED"),
    JSON.stringify(outcome.entries, null, 2),
  );

  // The run's browser is gone with its profile.
  assert.equal(outcome.profiles_left, 0);

  // The value is nowhere but the page.
  for (const [where, haystack] of [
    ["the job's view of request_fill", JSON.stringify(job)],
    ["the sidecar's stdout", job.sidecarStdout || ""],
    ["the machine vault's audit log", JSON.stringify(outcome)],
    ["the harness's stdout", stdout],
    ["the harness's stderr", stderr],
  ]) {
    assert.ok(!haystack.includes(password), `the password reached ${where}`);
  }
});
