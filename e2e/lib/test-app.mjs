/**
 * A purpose-built local web app for the extension / agent-test-login e2e (ADR-0048, Phase 1a).
 *
 * Real register and login forms backed by an in-memory user map. Passwords are kept only as
 * scrypt hashes with a per-user salt; request bodies are never logged and a password is never
 * echoed into any response. Dependency-free: node:http and node:crypto only.
 *
 *   node e2e/lib/test-app.mjs [--port 47800] [--host 127.0.0.1]
 */

import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PAGES = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "suites",
  "extension",
  "pages",
  "test-app",
);

const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const page = (name) => fs.readFileSync(path.join(PAGES, name), "utf8");

function hashPassword(password, salt = crypto.randomBytes(16)) {
  return { salt, hash: crypto.scryptSync(password, salt, 32) };
}

function verifyPassword(password, record) {
  const candidate = crypto.scryptSync(password, record.salt, 32);
  return crypto.timingSafeEqual(candidate, record.hash);
}

function errorPage(message, back) {
  return `<!doctype html>
<meta charset="utf-8" />
<title>Error</title>
<h1>Error</h1>
<p id="error" role="alert">${escapeHtml(message)}</p>
<p><a href="${back}">Back</a></p>
`;
}

async function readForm(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 64 * 1024) throw new Error("body too large");
    chunks.push(chunk);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

export function startTestApp({ port = 47800, host = "127.0.0.1" } = {}) {
  /** username -> { salt, hash }. Exposed so a test can assert a hash exists, never a password. */
  const users = new Map();

  const send = (res, status, body, headers = {}) => {
    res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...headers });
    res.end(body);
  };

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://localhost");
      if (req.method === "GET") {
        if (url.pathname === "/" || url.pathname === "/register") return send(res, 200, page("register.html"));
        if (url.pathname === "/login") return send(res, 200, page("login.html"));
        if (url.pathname === "/welcome") {
          const u = url.searchParams.get("u") ?? "";
          return send(res, 200, page("welcome.html").replace("{{username}}", escapeHtml(u)));
        }
        return send(res, 404, errorPage("Not found", "/"));
      }
      if (req.method === "POST" && (url.pathname === "/register" || url.pathname === "/login")) {
        const form = await readForm(req);
        const username = (form.get("username") ?? "").trim();
        const password = form.get("password") ?? "";
        if (url.pathname === "/register") {
          if (!username || !password) return send(res, 400, errorPage("Username and password are required.", "/register"));
          if (password !== (form.get("confirm") ?? "")) return send(res, 400, errorPage("Passwords do not match.", "/register"));
          if (users.has(username)) return send(res, 409, errorPage("That account already exists.", "/register"));
          users.set(username, hashPassword(password));
          return send(res, 302, "", { location: "/login" });
        }
        const record = users.get(username);
        if (!record || !verifyPassword(password, record)) {
          return send(res, 401, errorPage("Invalid username or password.", "/login"));
        }
        return send(res, 302, "", { location: `/welcome?u=${encodeURIComponent(username)}` });
      }
      return send(res, 405, errorPage("Method not allowed", "/"));
    } catch {
      return send(res, 400, errorPage("Bad request", "/"));
    }
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const { port: actual } = server.address();
      const shown = host.includes(":") ? `[${host}]` : host;
      resolve({
        url: `http://${shown}:${actual}`,
        users,
        close: () => new Promise((r) => { server.close(() => r()); server.closeAllConnections?.(); }),
      });
    });
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const arg = (name, fallback) => {
    const i = process.argv.indexOf(`--${name}`);
    return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
  };
  const app = await startTestApp({ port: Number(arg("port", 47800)), host: arg("host", "127.0.0.1") });
  console.log(`test app listening on ${app.url} (register: ${app.url}/register)`);
}
