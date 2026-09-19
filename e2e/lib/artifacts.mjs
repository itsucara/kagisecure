/**
 * The contract between a suite and the runner.
 *
 * A suite does not know it is being reported on. It writes a JUnit XML file at `E2E_JUNIT`, drops
 * whatever evidence it wants into `E2E_ARTIFACTS`, and appends one line to `manifest.jsonl` for
 * each piece of evidence it wants shown next to a scenario. The runner reads only those two
 * things, so a suite written in another language — the XCUITest bundle phase 2 adds, which will
 * convert an `.xcresult` rather than call this module — contributes to the same report by writing
 * the same two files.
 *
 * The manifest is JSON Lines rather than one JSON document on purpose: suites append to it from
 * several tests, sometimes concurrently, and an append-only line format has no read-modify-write
 * window to lose an entry in.
 */

import fs from "node:fs";
import path from "node:path";

/** Where this suite may write evidence. Absent when a suite is run directly, outside the runner. */
export function artifactDir() {
  return process.env.E2E_ARTIFACTS || null;
}

/**
 * Record one piece of evidence against a scenario.
 *
 * `test` must equal the JUnit `testcase` name exactly, which for a `node:test` suite is the string
 * passed to `test(...)`. `kind` is `"image"` or `"log"`; the runner embeds images inline and
 * renders logs as text.
 */
export function record(test, file, { label, kind = "log" } = {}) {
  const dir = artifactDir();
  if (!dir) return;
  const line = JSON.stringify({
    test,
    file: path.basename(file),
    label: label || path.basename(file),
    kind,
  });
  fs.appendFileSync(path.join(dir, "manifest.jsonl"), `${line}\n`);
}

/** Write `text` to `name` inside the artifact directory and record it against `test`. */
export function recordText(test, name, text, label) {
  const dir = artifactDir();
  if (!dir) return;
  const file = path.join(dir, name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  record(test, file, { label: label || name, kind: "log" });
}

/**
 * Screenshot a Playwright page into the artifact directory and record it.
 *
 * A no-op when there is no artifact directory, so the browser suite is still runnable on its own
 * with `node --test` and simply produces no evidence.
 */
export async function screenshot(page, test, name, label) {
  const dir = artifactDir();
  if (!dir) return;
  const file = path.join(dir, `${name}.png`);
  await page.screenshot({ path: file });
  record(test, file, { label: label || name, kind: "image" });
}

/** A filesystem-safe version of an arbitrary scenario name. */
export function slug(text) {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 80);
}
