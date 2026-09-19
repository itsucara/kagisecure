/**
 * What the report says about the machine the run happened on.
 *
 * A green report is only evidence if you can tell what it was green *against*. Every fact here is
 * measured at run time rather than configured, and anything that cannot be measured is reported as
 * "not found" rather than omitted — a missing row would read as "not relevant" when what it
 * actually means is "this run did not have it".
 */

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

function run(command, args, options = {}) {
  try {
    return execFileSync(command, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 20_000,
      ...options,
    }).trim();
  } catch {
    return null;
  }
}

function firstLine(text) {
  return text ? text.split("\n")[0].trim() : null;
}

/** The version string a Chromium-family browser reports, or null when it is not installed. */
function browserVersion(appPath) {
  if (!fs.existsSync(appPath)) return null;
  const plist = path.join(appPath, "Contents", "Info.plist");
  return run("plutil", ["-extract", "CFBundleShortVersionString", "raw", plist]);
}

/**
 * Collect the environment header.
 *
 * @param {string} repoRoot
 * @returns {Promise<{group: string, rows: [string, string][]}[]>}
 */
export async function describeEnvironment(repoRoot) {
  const git = (args) => run("git", args, { cwd: repoRoot });
  const commit = git(["rev-parse", "--short", "HEAD"]);
  const branch = git(["rev-parse", "--abbrev-ref", "HEAD"]);
  const dirty = git(["status", "--porcelain"]);

  const teamId = run("security", [
    "find-identity",
    "-v",
    "-p",
    "codesigning",
  ]);
  const hasDeveloperId = Boolean(teamId && teamId.includes("Developer ID Application"));

  return [
    {
      group: "Run",
      rows: [
        ["Date", new Date().toISOString()],
        ["Host", os.hostname()],
        ["User", os.userInfo().username],
      ],
    },
    {
      group: "Repository",
      rows: [
        ["Commit", commit || "unknown"],
        ["Branch", branch || "unknown"],
        ["Working tree", dirty ? `dirty (${dirty.split("\n").length} file(s))` : "clean"],
      ],
    },
    {
      group: "Toolchain",
      rows: [
        ["macOS", `${run("sw_vers", ["-productVersion"]) || "?"} (${os.arch()})`],
        ["Xcode", firstLine(run("xcodebuild", ["-version"])) || "not found"],
        ["Rust", run("rustc", ["--version"]) || "not found"],
        ["Cargo", run("cargo", ["--version"]) || "not found"],
        ["Node", process.version],
      ],
    },
    {
      group: "Browsers",
      rows: [
        [
          "Microsoft Edge",
          browserVersion("/Applications/Microsoft Edge.app") || "not installed",
        ],
        ["Google Chrome", browserVersion("/Applications/Google Chrome.app") || "not installed"],
        ["Safari", browserVersion("/Applications/Safari.app") || "system"],
      ],
    },
    {
      group: "Signing",
      rows: [
        [
          "Mode",
          hasDeveloperId
            ? "ad-hoc for the harness; a Developer ID identity is present in the keychain"
            : "ad-hoc (no Developer ID Application identity in the keychain)",
        ],
        [
          "Consequence",
          "Peer code-signature checks report UNVERIFIED under ad-hoc signing (ADR-0015).",
        ],
      ],
    },
  ];
}
