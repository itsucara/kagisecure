#!/usr/bin/env node
/**
 * Suite D's adapter: run the XCUITest bundle, and turn what comes out into the two files the
 * phase-1 runner reads (docs/e2e-harness.md §3).
 *
 * The runner knows nothing about Xcode. It gives this script `E2E_JUNIT`, `E2E_ARTIFACTS`,
 * `E2E_RUN_DIR` and `E2E_REPO_ROOT`, and afterwards reads a JUnit document and a
 * `manifest.jsonl`. So this script:
 *
 *   1. runs `xcodebuild test` against the `KagisecureUITests` scheme, passing the artifact
 *      directory through to the test process with the `TEST_RUNNER_` prefix;
 *   2. converts the `.xcresult` into JUnit XML;
 *   3. recognises the one failure that is not about kagisecure — macOS refusing the test runner
 *      permission to drive another process — and reports it as a skip with the one-line fix;
 *   4. rewrites the scenario names in both the JUnit document and the manifest the test bundle
 *      wrote, so the report reads as English rather than as Swift selectors.
 *
 * # Why the screenshots are not extracted from the `.xcresult`
 *
 * They could be: `xcresulttool export attachments` will do it. But the shape of an `.xcresult` and
 * the spelling of the commands that read one have changed in every recent Xcode, and a suite whose
 * evidence disappears on an Xcode upgrade is a suite nobody trusts. The test bundle therefore
 * writes the PNG it wants into `E2E_ARTIFACTS` itself and appends its own manifest line — the same
 * contract every other suite follows — *and* attaches the same screenshot to the result bundle for
 * anybody opening it in Xcode. See `UITestCase.capture`.
 */

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(import.meta.dirname, "..", "..", "..");
const JUNIT = process.env.E2E_JUNIT || path.join(import.meta.dirname, "junit.xml");
const ARTIFACTS = process.env.E2E_ARTIFACTS || "";
const RUN_DIR = process.env.E2E_RUN_DIR || "/tmp";

const PROJECT = path.join(REPO_ROOT, "apps", "macos", "Kagisecure.xcodeproj");
const SCHEME = "KagisecureUITests";
const RESULT_BUNDLE = path.join(RUN_DIR, "app.xcresult");

/**
 * The message `XCTRunner` produces when macOS will not let it drive another process.
 *
 * A machine with developer mode off can refuse the test runner outright, and then *every* scenario
 * fails with this rather than with anything about kagisecure — a wall of red that says nothing
 * about the product. It is recognised after the fact rather than predicted beforehand: an earlier
 * version of this script probed `security authorize system.privilege.taskport` first and got the
 * answer wrong, because the right not being *cached* is not the same as it being refused, and the
 * suite skipped itself on a machine where it ran perfectly well. Asking the thing that knows is
 * better than asking something that correlates with it.
 */
const RUNNER_REFUSED =
  /failed to initialize for UI testing|not authorized for performing UI testing actions/i;

/**
 * What a scenario looks like when the authorization is withdrawn *while it is running*.
 *
 * On a machine whose credential lapses mid-run, the scenario that is in flight does not get the
 * polite refusal — the connection to the app it is driving simply goes away, or the teardown cannot
 * terminate it, and the *next* scenario gets `RUNNER_REFUSED`. On their own both messages are
 * ambiguous and might mean the app crashed or hung, which is exactly what a suite like this exists
 * to catch. So they count as a refusal **only in a run that was explicitly refused somewhere
 * else**; in a run where nothing was refused, either one is a failure and is reported as one.
 */
const CONNECTION_LOST =
  /lost connection to the application|failed to terminate com\.kagisecure/i;

const AUTHORIZATION_HELP = [
  "macOS would not let the test runner drive the app, so every scenario failed before it began.",
  "",
  "This is the `system.privilege.taskport` authorization right, which developer mode grants.",
  "Grant it once, either for this login session:",
  "",
  "    security authorize -ue system.privilege.taskport",
  "",
  "or permanently, which is what Xcode itself offers the first time you run a test:",
  "",
  "    sudo DevToolsSecurity -enable",
  "",
  "Both need an administrator. Neither is something `make e2e` will do for you: this suite",
  "refuses to change the security posture of the machine it is measuring.",
].join("\n");

/** XML-escape a string for a text node or an attribute value. */
function escapeXml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

/**
 * `testFirstRunCreatesAVault()` → `first run creates a vault`.
 *
 * The runner shows the JUnit `testcase` name verbatim, next to sentences from three other suites.
 * A Swift selector in that list is an eyesore and, worse, is the thing a reader has to translate
 * before they know what failed. The transformation is here rather than in Swift because the
 * manifest and the JUnit document have to agree on the result exactly, and one implementation
 * cannot disagree with itself.
 */
function prettify(name) {
  const text = String(name)
    .replace(/\(\)$/, "")
    .replace(/^test/, "")
    // `aVault` → `a Vault`, and `TTLSlider` → `TTL Slider`: two passes, because a run of capitals
    // followed by a capitalised word is a different boundary from a lower-case letter followed by
    // a capital, and one regex that tried to be both would swallow acronyms.
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2");
  const words = text
    .split(/\s+/)
    .filter(Boolean)
    // An all-capitals word is an acronym and keeps its case; everything else is prose.
    .map((word) => (/^[A-Z]{2,}$/.test(word) ? word : word.toLowerCase()));
  return words.join(" ") || String(name);
}

/** Walk the `testNodes` tree `xcresulttool` produces and collect the leaves. */
function collectCases(node, cases) {
  if (!node || typeof node !== "object") return cases;
  if (node.nodeType === "Test Case") {
    const failures = [];
    const walkFailures = (n) => {
      if (!n || typeof n !== "object") return;
      if (n.nodeType === "Failure Message" && n.name) failures.push(n.name);
      for (const child of n.children || []) walkFailures(child);
    };
    walkFailures(node);

    // `duration` looks like "1.2s" or "0.04s"; absent on a case that never ran.
    const seconds = Number.parseFloat(String(node.duration || "0").replace(/[^0-9.]/g, "")) || 0;
    const result = String(node.result || "").toLowerCase();
    cases.push({
      name: node.name || node.nodeIdentifier || "unnamed",
      status: result === "passed" ? "passed" : result === "skipped" ? "skipped" : "failed",
      seconds,
      message: failures.join("\n"),
    });
    return cases;
  }
  for (const child of node.children || []) collectCases(child, cases);
  return cases;
}

/** Read the result bundle back as a list of scenarios. */
function readResultBundle() {
  const read = spawnSync(
    "xcrun",
    ["xcresulttool", "get", "test-results", "tests", "--path", RESULT_BUNDLE, "--compact"],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );
  if (read.status !== 0) {
    throw new Error(
      `xcresulttool could not read ${RESULT_BUNDLE}:\n${read.stdout}\n${read.stderr}`,
    );
  }
  const parsed = JSON.parse(read.stdout);
  const cases = [];
  for (const node of parsed.testNodes || []) collectCases(node, cases);
  return cases;
}

/** Write the JUnit document the runner reads back. */
function writeJunit(cases) {
  const failures = cases.filter((c) => c.status === "failed").length;
  const skipped = cases.filter((c) => c.status === "skipped").length;
  const seconds = cases.reduce((total, c) => total + c.seconds, 0);

  const body = cases
    .map((testcase) => {
      const open =
        `    <testcase name="${escapeXml(testcase.name)}" classname="app" ` +
        `time="${testcase.seconds.toFixed(3)}"`;
      if (testcase.status === "passed") return `${open} />`;
      const tag = testcase.status === "skipped" ? "skipped" : "failure";
      const first = (testcase.message || "").split("\n")[0] || testcase.status;
      return (
        `${open}>\n` +
        `      <${tag} message="${escapeXml(first)}">${escapeXml(testcase.message)}</${tag}>\n` +
        `    </testcase>`
      );
    })
    .join("\n");

  const document =
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<testsuites>\n` +
    `  <testsuite name="app" tests="${cases.length}" failures="${failures}" ` +
    `skipped="${skipped}" time="${seconds.toFixed(3)}">\n` +
    `${body}\n` +
    `  </testsuite>\n` +
    `</testsuites>\n`;

  fs.mkdirSync(path.dirname(JUNIT), { recursive: true });
  fs.writeFileSync(JUNIT, document);
}

/**
 * Rewrite the `test` key of every manifest line through `prettify`.
 *
 * The test bundle writes the raw selector, because that is the only name it reliably knows about
 * itself; the runner joins the manifest to the JUnit document on this string, so both sides have to
 * be transformed by the same function.
 */
function prettifyManifest() {
  if (!ARTIFACTS) return;
  const manifest = path.join(ARTIFACTS, "manifest.jsonl");
  if (!fs.existsSync(manifest)) return;
  const lines = fs
    .readFileSync(manifest, "utf8")
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => {
      try {
        const entry = JSON.parse(line);
        entry.test = prettify(entry.test);
        return JSON.stringify(entry);
      } catch {
        return line;
      }
    });
  fs.writeFileSync(manifest, lines.length ? `${lines.join("\n")}\n` : "");
}

/** One synthesised scenario, for the cases where nothing ran and the reason is worth reading. */
function reportOnly(name, status, message) {
  writeJunit([{ name, status, seconds: 0, message }]);
  console.log(`${status}: ${name}\n${message}`);
}

async function main() {
  if (process.platform !== "darwin") {
    reportOnly(
      "the macOS app suite",
      "skipped",
      "Suite D drives the macOS app through XCUITest, which needs macOS.",
    );
    return 0;
  }

  fs.rmSync(RESULT_BUNDLE, { recursive: true, force: true });

  const arguments_ = [
    "-project",
    PROJECT,
    "-scheme",
    SCHEME,
    "-destination",
    "platform=macOS",
    "-configuration",
    "Debug",
    "-resultBundlePath",
    RESULT_BUNDLE,
    // The same ad-hoc signing the Makefile uses. A clean checkout has no developer
    // account (CI didn't either, before it was removed on 2026-09-19), and this suite must build
    // there too (ADR-0025).
    "CODE_SIGN_STYLE=Manual",
    "CODE_SIGN_IDENTITY=-",
    "DEVELOPMENT_TEAM=",
    "test",
  ];

  const environment = {
    ...process.env,
    // `xcodebuild` passes anything prefixed `TEST_RUNNER_` into the test process with the prefix
    // stripped. It is the only channel from here into the XCUITest bundle, which runs in its own
    // process under its own runner app.
    TEST_RUNNER_E2E_ARTIFACTS: ARTIFACTS,
    TEST_RUNNER_E2E_REPO_ROOT: REPO_ROOT,
    TEST_RUNNER_E2E_KEEP: process.env.E2E_KEEP || "",
  };

  const status = await new Promise((resolve) => {
    const child = spawn("xcodebuild", arguments_, {
      cwd: REPO_ROOT,
      env: environment,
      stdio: ["ignore", "inherit", "inherit"],
    });
    child.on("error", (error) => {
      console.error(`could not run xcodebuild: ${error.message}`);
      resolve(127);
    });
    child.on("close", (code) => resolve(code === null ? 1 : code));
  });

  if (!fs.existsSync(RESULT_BUNDLE)) {
    reportOnly(
      "the macOS app suite",
      "failed",
      `xcodebuild exited ${status} and produced no result bundle at ${RESULT_BUNDLE}. ` +
        "The suite log has its output.",
    );
    return 1;
  }

  const raw = readResultBundle();

  // The runner never got off the ground at all. One skip with the fix, rather than a wall of red
  // in which not one failure is about kagisecure.
  if (raw.length > 0 && raw.every((c) => RUNNER_REFUSED.test(`${c.name} ${c.message}`))) {
    reportOnly("the macOS app suite", "skipped", AUTHORIZATION_HELP);
    return 0;
  }

  // Or it got off the ground and was refused part way through, which is what a machine whose
  // authorization lapses mid-run looks like. Those scenarios did not run, so they are skipped
  // rather than failed — and the reason travels with them into the report, so a suite that skips
  // half of itself is visible rather than quietly green.
  const wasRefused = raw.some((c) => RUNNER_REFUSED.test(c.message));
  const refused = (testcase) =>
    RUNNER_REFUSED.test(testcase.message) ||
    (wasRefused && CONNECTION_LOST.test(testcase.message));

  const cases = raw.map((testcase) => ({
    ...testcase,
    name: prettify(testcase.name),
    status: refused(testcase) ? "skipped" : testcase.status,
    message: refused(testcase)
      ? `${testcase.message}\n\n${AUTHORIZATION_HELP}`
      : testcase.message,
  }));
  writeJunit(cases);
  prettifyManifest();

  if (cases.length === 0) {
    reportOnly(
      "the macOS app suite",
      "failed",
      `xcodebuild exited ${status} without running a single scenario.`,
    );
    return 1;
  }

  // The result bundle is the authority on pass and fail, and `xcodebuild`'s exit code is not
  // consulted past this point. It cannot be: a run that macOS refused exits non-zero and contains
  // nothing but scenarios that never started, and a suite that reported those as a failure would
  // be reporting the machine's configuration as a defect in kagisecure. The two cases where the
  // exit code *is* the only evidence — no result bundle, or a bundle with no scenarios in it —
  // are both handled above, and both return 1.
  const failed = cases.filter((c) => c.status === "failed").length;
  return failed > 0 ? 1 : 0;
}

process.exitCode = await main();
