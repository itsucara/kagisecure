#!/usr/bin/env node
/**
 * The kagisecure end-to-end runner.
 *
 * Usage:
 *
 *   node e2e/run.mjs                 every suite except D (the macOS app; see E2E_GUI below)
 *   node e2e/run.mjs --suite mcp     one suite (comma-separated for several)
 *   E2E_KEEP=1 node e2e/run.mjs      keep the temporary vaults, sockets and artifacts
 *   E2E_GUI=1 node e2e/run.mjs       also run suite D, which takes over the mouse and keyboard
 *
 * `make e2e` and `make e2e SUITE=mcp` are the documented spellings; this file is what they call.
 *
 * Suite D drives the real app through XCUITest, which means real clicks and keystrokes at the
 * window server for the better part of half an hour. It is left out of a plain `make e2e` (and
 * refused if named explicitly) unless `E2E_GUI=1` says the Mac is not in use right now.
 *
 * # What the runner knows about a suite
 *
 * Almost nothing, on purpose. A suite is a directory under `e2e/suites/` containing a `suite.json`
 * that names a command to run. The runner gives it a temporary directory, a path to write JUnit
 * XML to, and a directory to drop evidence in; afterwards it reads exactly those two things back.
 * It does not know that today's three suites happen to be Node test files, and phase 2's XCUITest
 * bundle will be a shell script that converts an `.xcresult` — which needs no change here.
 *
 * # Why Node rather than `cargo xtask e2e`
 *
 * See `docs/e2e-harness.md` §2. The short version: two of the three suites are already Node
 * (Playwright drives the browser one, and the MCP sidecar speaks newline-delimited JSON-RPC on
 * stdio, which needs no client library at all), a Rust runner would have to shell out to Node
 * anyway, and `node --test --test-reporter=junit` gives per-scenario JUnit for free.
 */

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describeEnvironment } from "./lib/environment.mjs";
import { parseTestcases, renderJunit } from "./lib/junit.mjs";
import { renderReport } from "./lib/report.mjs";

const E2E_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(E2E_DIR, "..");
const SUITES_DIR = path.join(E2E_DIR, "suites");
const REPORT_DIR = path.join(E2E_DIR, "report");
const TMP_DIR = path.join(E2E_DIR, "tmp");

/**
 * Where a suite's sockets go.
 *
 * **Not** under `e2e/tmp/`. A unix domain socket path has to fit in `sockaddr_un::sun_path`, which
 * is 104 bytes on macOS, and `<repo>/e2e/tmp/<run id>/<suite>/daemon.sock` is already most of that
 * before you account for anybody's checkout living somewhere deeper than mine. The failure is not
 * subtle — the daemon refuses to start with "local socket name length exceeds capacity of
 * sun_path" — but it is exactly the kind of thing that works on the author's machine and not on
 * a contributor's, so the runtime state goes somewhere short and stays there.
 */
const SOCKET_ROOT = "/tmp";

const KEEP = process.env.E2E_KEEP === "1";

/**
 * Whether suite D — the macOS app, driven through XCUITest — is allowed to run.
 *
 * It takes over the mouse and keyboard for the better part of half an hour: XCUITest synthesizes
 * real clicks and keystrokes at the window server, so anything else the machine is doing during
 * that window gets typed into or clicked on instead. A `make e2e` run with every suite selected
 * defaulting to that would surprise whoever typed it. `E2E_GUI=1` is the opt-in that says the Mac
 * is not in use right now; without it, suite D is left out rather than attempted.
 */
const GUI_SUITE = "app";
const GUI_ENABLED = process.env.E2E_GUI === "1";

function parseArgs(argv) {
  const options = { suites: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--suite" || arg === "-s") {
      options.suites = String(argv[i + 1] || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      i += 1;
    } else if (arg.startsWith("--suite=")) {
      options.suites = arg
        .slice("--suite=".length)
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    } else if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else {
      throw new Error(`unknown argument ${JSON.stringify(arg)}`);
    }
  }
  if (!options.suites && process.env.SUITE) {
    options.suites = process.env.SUITE.split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  return options;
}

function discoverSuites() {
  if (!fs.existsSync(SUITES_DIR)) return [];
  return fs
    .readdirSync(SUITES_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(SUITES_DIR, entry.name, "suite.json"))
    .filter((file) => fs.existsSync(file))
    .map((file) => {
      const definition = JSON.parse(fs.readFileSync(file, "utf8"));
      return { ...definition, dir: path.dirname(file) };
    })
    .sort((a, b) => (a.order ?? 100) - (b.order ?? 100));
}

/** Run one command, streaming its output to the terminal and tee-ing it into `logPath`. */
function runCommand(command, args, { cwd, env, logPath, timeoutSeconds }) {
  return new Promise((resolve) => {
    const log = fs.createWriteStream(logPath, { flags: "a" });
    log.write(`$ ${[command, ...args].join(" ")}\n`);
    const child = spawn(command, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"] });

    let timer = null;
    let timedOut = false;
    if (timeoutSeconds) {
      timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, timeoutSeconds * 1000);
    }

    for (const stream of ["stdout", "stderr"]) {
      child[stream].on("data", (chunk) => {
        process.stdout.write(chunk);
        log.write(chunk);
      });
    }

    child.on("error", (error) => {
      log.write(`\nfailed to spawn: ${error.message}\n`);
      log.end();
      if (timer) clearTimeout(timer);
      resolve({ code: 127, timedOut: false, spawnError: error });
    });

    child.on("close", (code, signal) => {
      if (timer) clearTimeout(timer);
      if (timedOut) log.write(`\nkilled after ${timeoutSeconds}s\n`);
      log.end();
      resolve({ code: code === null ? 1 : code, signal, timedOut });
    });
  });
}

function readManifest(artifactDir) {
  const file = path.join(artifactDir, "manifest.jsonl");
  if (!fs.existsSync(file)) return new Map();
  const byTest = new Map();
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    if (!line.trim()) continue;
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }
    const list = byTest.get(entry.test) || [];
    list.push({
      label: entry.label,
      kind: entry.kind,
      path: path.join(artifactDir, entry.file),
    });
    byTest.set(entry.test, list);
  }
  return byTest;
}

async function runSuite(definition, runId) {
  const started = Date.now();
  const artifactDir = path.join(TMP_DIR, runId, definition.name);
  const socketDir = path.join(SOCKET_ROOT, `kse2e-${runId}-${definition.name}`);
  const junitPath = path.join(artifactDir, "junit.xml");
  const logPath = path.join(artifactDir, "suite.log");

  fs.mkdirSync(artifactDir, { recursive: true });
  fs.mkdirSync(socketDir, { recursive: true, mode: 0o700 });

  const env = {
    ...process.env,
    // The toolchain this repo documents. A `make e2e` from a GUI-launched terminal otherwise has
    // no rustup on PATH, and the failure reads as "cargo: command not found" three layers down.
    PATH: `/opt/homebrew/opt/rustup/bin:${process.env.PATH}`,
    E2E_JUNIT: junitPath,
    E2E_ARTIFACTS: artifactDir,
    E2E_RUN_DIR: socketDir,
    E2E_REPO_ROOT: REPO_ROOT,
    E2E_KEEP: KEEP ? "1" : "",
  };

  console.log(`\n\x1b[1m━━ suite: ${definition.name} — ${definition.title}\x1b[0m`);

  // Build steps first, so a suite never runs against a stale binary and a build failure is
  // reported as a suite failure rather than as a mysterious scenario failure.
  for (const step of definition.build || []) {
    const [command, ...args] = step;
    console.log(`   building: ${step.join(" ")}`);
    const result = await runCommand(command, args, {
      cwd: REPO_ROOT,
      env,
      logPath,
      timeoutSeconds: 900,
    });
    if (result.code !== 0) {
      return {
        name: definition.name,
        title: definition.title,
        description: definition.description,
        seconds: (Date.now() - started) / 1000,
        cases: [
          {
            name: `build: ${step.join(" ")}`,
            classname: definition.name,
            seconds: (Date.now() - started) / 1000,
            status: "failed",
            message: `build step exited ${result.code}`,
            detail: fs.readFileSync(logPath, "utf8").slice(-4000),
            artifacts: [{ label: "suite log", kind: "log", path: logPath }],
          },
        ],
        exitCode: result.code,
        artifactDir,
        socketDir,
      };
    }
  }

  const [command, ...args] = definition.command.map((part) =>
    part.replaceAll("${E2E_JUNIT}", junitPath).replaceAll("${E2E_ARTIFACTS}", artifactDir),
  );
  const result = await runCommand(command, args, {
    cwd: definition.dir,
    env,
    logPath,
    timeoutSeconds: definition.timeoutSeconds || 1800,
  });

  const cases = fs.existsSync(junitPath)
    ? parseTestcases(fs.readFileSync(junitPath, "utf8"))
    : [];
  const artifacts = readManifest(artifactDir);
  for (const testcase of cases) {
    testcase.classname = definition.name;
    testcase.artifacts = artifacts.get(testcase.name) || [];
  }

  // A suite that exited non-zero without producing a failing case — a crash before the reporter
  // flushed, a timeout, a missing binary — must not be able to report itself green.
  const reportedFailure = cases.some((c) => c.status === "failed");
  if (result.code !== 0 && !reportedFailure) {
    cases.push({
      name: `${definition.name}: the suite did not finish`,
      classname: definition.name,
      seconds: 0,
      status: "failed",
      message: result.timedOut
        ? `timed out after ${definition.timeoutSeconds || 1800}s`
        : `the suite process exited ${result.code} without reporting a failing scenario`,
      detail: fs.readFileSync(logPath, "utf8").slice(-8000),
      artifacts: [{ label: "suite log", kind: "log", path: logPath }],
    });
  }

  // The whole suite's output is worth having next to a failure, and worth not having next to a
  // clean run — an embedded 200 KB log in a green report is noise nobody reads.
  if (cases.some((c) => c.status === "failed") && fs.existsSync(logPath)) {
    const failing = cases.find((c) => c.status === "failed");
    failing.artifacts = [
      ...(failing.artifacts || []),
      { label: "suite log (tail)", kind: "log", path: logPath },
    ];
  }

  return {
    name: definition.name,
    title: definition.title,
    description: definition.description,
    note: definition.note,
    seconds: (Date.now() - started) / 1000,
    cases,
    exitCode: result.code,
    artifactDir,
    socketDir,
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const available = discoverSuites();

  if (options.help) {
    console.log("usage: node e2e/run.mjs [--suite NAME[,NAME...]]");
    console.log(`suites: ${available.map((s) => s.name).join(", ")}`);
    console.log(
      `suite "${GUI_SUITE}" takes over the mouse and keyboard for ~30 minutes and is left out ` +
        `unless E2E_GUI=1 is set (run it only when the Mac is not in use)`,
    );
    return 0;
  }

  let selected = available;
  if (options.suites) {
    const known = new Set(available.map((s) => s.name));
    const unknown = options.suites.filter((name) => !known.has(name));
    if (unknown.length > 0) {
      console.error(
        `e2e: no such suite: ${unknown.join(", ")}. Known suites: ` +
          `${available.map((s) => s.name).join(", ")}`,
      );
      return 2;
    }
    selected = available.filter((s) => options.suites.includes(s.name));

    // Named explicitly, so refuse outright rather than silently dropping it — a `SUITE=app` that
    // quietly ran nothing would be a more confusing surprise than an error telling you the flag.
    if (!GUI_ENABLED && selected.some((s) => s.name === GUI_SUITE)) {
      console.error(
        `e2e: suite "${GUI_SUITE}" takes over the mouse and keyboard for about thirty minutes. ` +
          `Run it only when the Mac is not in use, with E2E_GUI=1 set, e.g.:\n\n` +
          `    E2E_GUI=1 make e2e SUITE=${GUI_SUITE}\n`,
      );
      return 2;
    }
  } else if (!GUI_ENABLED) {
    const excluded = selected.filter((s) => s.name === GUI_SUITE);
    selected = selected.filter((s) => s.name !== GUI_SUITE);
    for (const suite of excluded) {
      console.log(
        `   skip  ${suite.name.padEnd(10)} takes over the mouse and keyboard for ~30 minutes — ` +
          `set E2E_GUI=1 to include it`,
      );
    }
  }

  if (selected.length === 0) {
    console.error("e2e: no suites to run");
    return 2;
  }

  const runId = new Date().toISOString().replace(/[:.]/g, "-");
  const started = Date.now();
  const results = [];
  for (const definition of selected) {
    results.push(await runSuite(definition, runId));
  }
  const seconds = (Date.now() - started) / 1000;

  fs.mkdirSync(REPORT_DIR, { recursive: true });
  const environment = await describeEnvironment(REPO_ROOT);
  const command = `node e2e/run.mjs${options.suites ? ` --suite ${options.suites.join(",")}` : ""}`;
  fs.writeFileSync(
    path.join(REPORT_DIR, "index.html"),
    renderReport({ suites: results, environment, seconds, command }),
  );
  fs.writeFileSync(path.join(REPORT_DIR, "junit.xml"), renderJunit(results));

  const all = results.flatMap((r) => r.cases);
  const passed = all.filter((c) => c.status === "passed").length;
  const failed = all.filter((c) => c.status === "failed").length;
  const skipped = all.filter((c) => c.status === "skipped").length;

  console.log("\n\x1b[1m━━ summary\x1b[0m");
  for (const suite of results) {
    const p = suite.cases.filter((c) => c.status === "passed").length;
    const f = suite.cases.filter((c) => c.status === "failed").length;
    const s = suite.cases.filter((c) => c.status === "skipped").length;
    const mark = f > 0 ? "\x1b[31mFAIL\x1b[0m" : "\x1b[32mok\x1b[0m";
    console.log(
      `   ${mark}  ${suite.name.padEnd(10)} ${p} passed, ${f} failed, ${s} skipped` +
        `  (${suite.seconds.toFixed(1)}s)`,
    );
  }
  for (const testcase of all.filter((c) => c.status === "failed")) {
    console.log(`\n\x1b[31m   ✗ ${testcase.classname}: ${testcase.name}\x1b[0m`);
    console.log(`     ${(testcase.message || "").split("\n").join("\n     ")}`);
  }

  console.log(
    `\n   ${passed} passed, ${failed} failed, ${skipped} skipped in ${seconds.toFixed(1)}s`,
  );
  console.log(`   report  ${path.join(REPORT_DIR, "index.html")}`);
  console.log(`   junit   ${path.join(REPORT_DIR, "junit.xml")}`);

  if (KEEP) {
    for (const suite of results) {
      console.log(`   kept    ${suite.socketDir}  ${suite.artifactDir}`);
    }
  } else {
    for (const suite of results) {
      fs.rmSync(suite.socketDir, { recursive: true, force: true });
      fs.rmSync(suite.artifactDir, { recursive: true, force: true });
    }
    fs.rmSync(path.join(TMP_DIR, runId), { recursive: true, force: true });
  }

  return failed > 0 ? 1 : 0;
}

process.exitCode = await main();
