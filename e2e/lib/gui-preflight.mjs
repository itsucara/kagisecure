/**
 * What suite D needs from the Mac before it starts, checked rather than hoped for.
 *
 * XCUITest synthesizes real keystrokes, and they go through whatever input source is selected.
 * With an input method selected rather than a plain keyboard layout, a typed string is composed
 * rather than typed: the text that reaches a field is not the text the scenario sent, and on the
 * run that found this, System Settings came to the front on a synthesized keystroke and the
 * scenarios after it typed into System Settings instead of the app.
 *
 * Both checks read state; neither changes it. Switching the input source or quitting an app for
 * the person at the Mac is not this suite's to do — the same stance as the UI-testing
 * authorization (docs/e2e-harness.md §7.4): detect, say how to fix it, and stop.
 *
 * Unlike the authorization probe §7.4 warns about, these read the cause itself rather than
 * something correlated with it: the selected input sources *are* what the keystrokes go through.
 */

import { execFileSync } from "node:child_process";

/**
 * `InputSourceKind` values that are a plain keyboard layout, or not a typing source at all.
 *
 * "Non Keyboard Input Method" entries — the character palette, press-and-hold accents, the emoji
 * row — are selected on every Mac, whatever the person types with, and never compose keystrokes.
 * They must not count, or the check would refuse every machine.
 */
const LAYOUT_KINDS = new Set(["Keyboard Layout"]);
const HARMLESS_KINDS = new Set(["Non Keyboard Input Method"]);

/** Read a key of `com.apple.HIToolbox` as JSON (or raw text), or null when it is not there. */
function readHIToolbox(key, format = "json") {
  try {
    const plist = execFileSync("defaults", ["export", "com.apple.HIToolbox", "-"], {
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 10_000,
    });
    const value = execFileSync("plutil", ["-extract", key, format, "-o", "-", "-"], {
      input: plist,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "ignore"],
      timeout: 10_000,
    }).trim();
    return format === "json" ? JSON.parse(value) : value;
  } catch {
    return null;
  }
}

/** Whether a process with exactly this name is running. */
function isRunning(name) {
  try {
    execFileSync("pgrep", ["-x", name], { stdio: "ignore", timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Judge `AppleSelectedInputSources`.
 *
 * OK when a keyboard layout is selected and nothing selected composes keystrokes. Any other
 * `InputSourceKind` — "Input Mode", "Input Method", "Keyboard Input Method" — is an input method,
 * and refuses. An unreadable or empty list cannot be judged, and says so rather than refusing: a
 * guard that fails closed on a machine it does not understand is a guard people learn to switch
 * off.
 *
 * @param {unknown} selected the parsed array, or null when it could not be read
 * @param {string | null} currentLayout `AppleCurrentKeyboardLayoutInputSourceID`, for the message
 * @returns {{ status: "ok" | "refuse" | "unknown", detail: string }}
 */
export function judgeInputSources(selected, currentLayout = null) {
  if (!Array.isArray(selected) || selected.length === 0) {
    return {
      status: "unknown",
      detail: "could not read the selected input sources (com.apple.HIToolbox)",
    };
  }
  const kindOf = (entry) => String(entry?.InputSourceKind ?? "");
  const describe = (entry) =>
    entry?.["Input Mode"] ?? entry?.["Bundle ID"] ?? entry?.["KeyboardLayout Name"] ?? kindOf(entry);

  const composing = selected.filter(
    (entry) => !LAYOUT_KINDS.has(kindOf(entry)) && !HARMLESS_KINDS.has(kindOf(entry)),
  );
  const layouts = selected.filter((entry) => LAYOUT_KINDS.has(kindOf(entry)));

  if (composing.length > 0) {
    return {
      status: "refuse",
      detail:
        `the selected input source is an input method (${composing
          .map((entry) => `${describe(entry)}, kind "${kindOf(entry)}"`)
          .join("; ")}), not a keyboard layout` +
        (currentLayout ? `; the keyboard layout under it is ${currentLayout}` : ""),
    };
  }
  if (layouts.length === 0) {
    return {
      status: "refuse",
      detail: "no keyboard layout is selected as the input source",
    };
  }
  return {
    status: "ok",
    detail: `keyboard layout ${layouts.map(describe).join(", ")}`,
  };
}

/**
 * Run every check. `probe` is injectable so the judgement can be exercised without a Mac in any
 * particular state.
 *
 * @returns {{ refusals: string[], notes: string[] }}
 */
export function guiPreflight(probe = {}) {
  const {
    platform = process.platform,
    selectedInputSources = () => readHIToolbox("AppleSelectedInputSources"),
    currentKeyboardLayout = () => readHIToolbox("AppleCurrentKeyboardLayoutInputSourceID", "raw"),
    systemSettingsRunning = () => isRunning("System Settings"),
  } = probe;

  const refusals = [];
  const notes = [];
  if (platform !== "darwin") {
    notes.push("not macOS; nothing to check");
    return { refusals, notes };
  }

  const input = judgeInputSources(selectedInputSources(), currentKeyboardLayout());
  if (input.status === "refuse") {
    refusals.push(
      [
        `Input source: ${input.detail}.`,
        "",
        "XCUITest's keystrokes go through the selected input source, and an input method",
        "composes them instead of typing them: the text that reaches a field is not the text",
        "the scenario sent, and a stray keystroke can bring another app to the front.",
        "",
        "Switch to a plain keyboard layout (ABC, for example) from the input menu in the menu",
        "bar, then run again. You can switch back when the suite has finished.",
      ].join("\n"),
    );
  } else if (input.status === "unknown") {
    notes.push(`input source not checked: ${input.detail}`);
  } else {
    notes.push(`input source: ${input.detail}`);
  }

  if (systemSettingsRunning()) {
    refusals.push(
      [
        "System Settings is running.",
        "",
        "It has taken the keyboard focus from the app under test mid-run before, after which",
        "the scenarios typed into System Settings instead. Quit it, then run again.",
      ].join("\n"),
    );
  } else {
    notes.push("System Settings: not running");
  }

  return { refusals, notes };
}
