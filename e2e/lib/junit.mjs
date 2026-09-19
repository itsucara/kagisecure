/**
 * A JUnit XML reader and writer, in about a hundred lines and with no dependency.
 *
 * # Why not an XML library
 *
 * The runner needs to read whatever a suite produced and write one merged document. The dialect
 * involved is tiny — `testsuites`, `testsuite`, `testcase`, and the three child elements that say
 * a case did not pass — and it is produced by tools we control or can inspect: Node's own
 * `--test-reporter=junit`, and (in phase 2) an `.xcresult` conversion. Pulling a parser into the
 * dependency tree of a *security* project to read four element names is a bad trade, and this
 * project's own `deny.toml` is the reason the trade gets made explicitly rather than by habit.
 *
 * The parser is deliberately tolerant: it scans for `testcase` elements anywhere in the document
 * and ignores everything else, so a suite that wraps its cases in `testsuite` elements, or emits
 * `properties` and `system-out`, still reads correctly.
 */

const ENTITIES = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&apos;": "'",
};

/** Undo XML escaping, including the numeric character references Node's reporter emits. */
export function unescapeXml(text) {
  return String(text)
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(Number(dec)))
    .replace(/&(amp|lt|gt|quot|apos);/g, (m) => ENTITIES[m]);
}

/** Escape text for an XML attribute or text node. */
export function escapeXml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    // Control characters are not representable in XML 1.0 at all, not even as a reference, so
    // they are dropped rather than escaped. A stack trace with a stray \x01 in it would otherwise
    // produce a junit.xml that no CI system can parse.
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, "");
}

function parseAttributes(text) {
  const attributes = {};
  const pattern = /([\w:.-]+)\s*=\s*"([^"]*)"/g;
  let match;
  while ((match = pattern.exec(text)) !== null) {
    attributes[match[1]] = unescapeXml(match[2]);
  }
  return attributes;
}

/**
 * Read every `testcase` in `xml`.
 *
 * Returns `{ name, classname, file, seconds, status, message, detail }`, where `status` is one of
 * `"passed"`, `"failed"` or `"skipped"`.
 */
export function parseTestcases(xml) {
  const cases = [];
  const pattern = /<testcase\b([^>]*?)(\/>|>([\s\S]*?)<\/testcase>)/g;
  let match;
  while ((match = pattern.exec(xml)) !== null) {
    const attributes = parseAttributes(match[1]);
    const body = match[3] || "";

    let status = "passed";
    let message = "";
    let detail = "";

    const problem = /<(failure|error)\b([^>]*?)(\/>|>([\s\S]*?)<\/\1>)/.exec(body);
    const skipped = /<skipped\b([^>]*?)(\/>|>([\s\S]*?)<\/skipped>)/.exec(body);

    if (problem) {
      status = "failed";
      message = parseAttributes(problem[2]).message || "";
      detail = unescapeXml(problem[4] || "");
    } else if (skipped) {
      status = "skipped";
      message = parseAttributes(skipped[1]).message || "";
    }

    cases.push({
      name: attributes.name || "(unnamed)",
      classname: attributes.classname || "",
      file: attributes.file || "",
      seconds: Number(attributes.time || 0),
      status,
      message,
      detail,
    });
  }
  return cases;
}

/**
 * Render one merged JUnit document: one `testsuite` per e2e suite, in the order they ran.
 *
 * `suites` is `[{ name, seconds, cases }]`.
 */
export function renderJunit(suites) {
  const lines = ['<?xml version="1.0" encoding="utf-8"?>'];
  const totals = suites.reduce(
    (acc, s) => {
      for (const c of s.cases) {
        acc.tests += 1;
        if (c.status === "failed") acc.failures += 1;
        if (c.status === "skipped") acc.skipped += 1;
      }
      acc.seconds += s.seconds;
      return acc;
    },
    { tests: 0, failures: 0, skipped: 0, seconds: 0 },
  );

  lines.push(
    `<testsuites name="kagisecure-e2e" tests="${totals.tests}" failures="${totals.failures}"` +
      ` errors="0" skipped="${totals.skipped}" time="${totals.seconds.toFixed(3)}">`,
  );

  for (const suite of suites) {
    const failures = suite.cases.filter((c) => c.status === "failed").length;
    const skipped = suite.cases.filter((c) => c.status === "skipped").length;
    lines.push(
      `  <testsuite name="${escapeXml(suite.name)}" tests="${suite.cases.length}"` +
        ` failures="${failures}" errors="0" skipped="${skipped}"` +
        ` time="${suite.seconds.toFixed(3)}">`,
    );
    for (const c of suite.cases) {
      const attributes =
        `name="${escapeXml(c.name)}" classname="${escapeXml(c.classname || suite.name)}"` +
        ` time="${c.seconds.toFixed(6)}"`;
      if (c.status === "passed") {
        lines.push(`    <testcase ${attributes}/>`);
      } else if (c.status === "skipped") {
        lines.push(`    <testcase ${attributes}>`);
        lines.push(`      <skipped message="${escapeXml(c.message)}"/>`);
        lines.push("    </testcase>");
      } else {
        lines.push(`    <testcase ${attributes}>`);
        lines.push(`      <failure message="${escapeXml(c.message)}" type="failure">`);
        lines.push(escapeXml(c.detail || c.message));
        lines.push("      </failure>");
        lines.push("    </testcase>");
      }
    }
    lines.push("  </testsuite>");
  }

  lines.push("</testsuites>");
  return `${lines.join("\n")}\n`;
}
