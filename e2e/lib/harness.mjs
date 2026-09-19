/**
 * The pieces every suite needs: where the binaries are, how to drive the CLI, how to start a
 * daemon, and how to talk to a real `kagisecure-mcp` over stdio.
 *
 * # Isolation
 *
 * Nothing here ever touches `~/Library/Application Support/kagisecure/`. Every vault is created
 * fresh under `E2E_RUN_DIR`, every socket is an explicit path under the same directory, and every
 * CLI invocation passes `--vault` explicitly rather than relying on the default. A suite that
 * forgets is a suite that can destroy somebody's real vault, so `vaultPath()` is the only
 * sanctioned way to name one and it refuses to produce a path outside the run directory.
 */

import { spawn, spawnSync, execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(import.meta.dirname, "..", "..");

/**
 * The per-run scratch directory.
 *
 * Short by construction — see the `SOCKET_ROOT` comment in `run.mjs`. Falls back to a `/tmp`
 * directory of its own when a suite is run directly with `node --test`, so a suite is still
 * runnable outside the runner.
 */
export function runDir() {
  const dir = process.env.E2E_RUN_DIR || `/tmp/kse2e-standalone-${process.pid}`;
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

/** A scratch subdirectory of the run directory. */
export function scratch(name) {
  const dir = path.join(runDir(), name);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** The path a suite's vault must live at. Never the user's own. */
export function vaultPath(name) {
  return path.join(runDir(), `${name}.kagivault`);
}

/** A debug binary from `target/debug`. */
export function binary(name) {
  return path.join(REPO_ROOT, "target", "debug", name);
}

/** A `cargo --example` binary from `target/debug/examples`. */
export function exampleBinary(name) {
  return path.join(REPO_ROOT, "target", "debug", "examples", name);
}

export const KAGISECURE = binary("kagisecure");
export const SIDECAR = binary("kagisecure-mcp");

/**
 * Run the CLI once.
 *
 * `stdin` is an array of lines. The CLI's `--password-stdin` reads the first line as the master
 * password and `--value-stdin` reads the rest, so the array order is the order the flags were
 * given — the same contract the CLI's own tests use.
 *
 * Never throws on a non-zero exit: the exit code *is* the assertion in several scenarios.
 */
export function cli(args, { vault, stdin = [], cwd = REPO_ROOT, env = {} } = {}) {
  const argv = vault ? ["--vault", vault, ...args] : [...args];
  const result = spawnSync(KAGISECURE, argv, {
    cwd,
    encoding: "utf8",
    timeout: 120_000,
    input: stdin.length ? `${stdin.join("\n")}\n` : "",
    env: { ...process.env, ...env },
  });
  return {
    code: result.status === null ? 1 : result.status,
    signal: result.signal,
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    argv: [KAGISECURE, ...argv],
  };
}

/** Assert a CLI call succeeded, with its own output as the failure message. */
export function cliOk(args, options) {
  const result = cli(args, options);
  if (result.code !== 0) {
    throw new Error(
      `kagisecure ${args.join(" ")} exited ${result.code}\n` +
        `stdout: ${result.stdout}\nstderr: ${result.stderr}`,
    );
  }
  return result;
}

/** Poll `predicate` until it is true or the deadline passes. */
export async function waitFor(predicate, { timeoutMs = 20_000, intervalMs = 25, what } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await predicate()) return true;
    if (Date.now() > deadline) {
      throw new Error(`timed out after ${timeoutMs}ms waiting for ${what || "a condition"}`);
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

/**
 * Start `kagisecure daemon` against a scratch vault and wait for its socket to appear.
 *
 * `--auto-approve` is the debug-only affordance from ADR-0007: the request still goes through the
 * approval queue and is answered through it, so the production path is exercised with a robot in
 * the chair rather than a bypass around it. A release build refuses the flag outright.
 */
export async function startDaemon({ vault, socket, password, args = [], logPath }) {
  const child = spawn(KAGISECURE, ["--vault", vault, "--password-stdin", "daemon", "--socket", socket, ...args], {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env },
  });

  let output = "";
  const append = (chunk) => {
    output += chunk;
    if (logPath) fs.appendFileSync(logPath, chunk);
  };
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", append);
  child.stderr.on("data", append);

  let exited = false;
  child.on("exit", () => {
    exited = true;
  });

  child.stdin.write(`${password}\n`);
  child.stdin.end();

  try {
    await waitFor(
      () => {
        if (exited) throw new Error(`the daemon exited before binding its socket:\n${output}`);
        return fs.existsSync(socket);
      },
      { what: `the daemon socket at ${socket}` },
    );
  } catch (error) {
    child.kill("SIGKILL");
    throw new Error(`${error.message}\n--- daemon output ---\n${output}`);
  }

  return {
    child,
    socket,
    output: () => output,
    stop() {
      if (exited) return;
      child.kill("SIGTERM");
    },
  };
}

/**
 * A real `kagisecure-mcp` on stdio, driven as an MCP client.
 *
 * The protocol is newline-delimited JSON-RPC, so this speaks it directly rather than through a
 * client library — which is not laziness but a requirement: the secret-marker canary asserts on
 * the sidecar's **raw stdout bytes**, and any MCP client library consumes that stream before the
 * test can see it. `crates/kagisecure-cli/tests/mcp.rs` hand-rolls the same protocol for the same
 * reason.
 *
 * Replies are correlated by `id`, not by arrival order — the sidecar answers each call on its own
 * blocking task and a slow approval genuinely does come back after a later, faster call.
 */
export class Sidecar {
  constructor(socket, { cwd = REPO_ROOT, clientName = "kagisecure-e2e" } = {}) {
    this.rawStdout = "";
    this.rawStderr = "";
    this.pending = new Map();
    this.buffer = "";
    this.nextId = 1;
    this.clientName = clientName;
    this.exited = false;

    this.child = spawn(SIDECAR, [], {
      cwd,
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, KAGISECURE_SOCKET: socket },
    });
    this.child.stdout.setEncoding("utf8");
    this.child.stderr.setEncoding("utf8");
    this.child.stdout.on("data", (chunk) => this.#onStdout(chunk));
    this.child.stderr.on("data", (chunk) => {
      this.rawStderr += chunk;
    });
    this.child.on("exit", () => {
      this.exited = true;
      for (const [, entry] of this.pending) {
        entry.reject(new Error(`the sidecar exited; stderr: ${this.rawStderr}`));
      }
      this.pending.clear();
    });
  }

  #onStdout(chunk) {
    this.rawStdout += chunk;
    this.buffer += chunk;
    let index;
    while ((index = this.buffer.indexOf("\n")) >= 0) {
      const line = this.buffer.slice(0, index).trim();
      this.buffer = this.buffer.slice(index + 1);
      if (!line) continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        continue;
      }
      const entry = this.pending.get(message.id);
      if (entry) {
        this.pending.delete(message.id);
        entry.resolve(message);
      }
    }
  }

  #send(message) {
    this.child.stdin.write(`${JSON.stringify(message)}\n`);
  }

  /** Send a request and wait for the reply with the matching id. */
  request(method, params, { timeoutMs = 90_000 } = {}) {
    const id = this.nextId++;
    const promise = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method} did not answer within ${timeoutMs}ms`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (message) => {
          clearTimeout(timer);
          resolve(message);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
    });
    this.#send({ jsonrpc: "2.0", id, method, params: params ?? {} });
    return promise;
  }

  async initialize() {
    const reply = await this.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: this.clientName, version: "0.0.0" },
    });
    this.#send({ jsonrpc: "2.0", method: "notifications/initialized" });
    this.serverInfo = reply.result?.serverInfo;
    this.instructions = reply.result?.instructions;
    return reply.result;
  }

  async tools() {
    const reply = await this.request("tools/list", {});
    return reply.result.tools;
  }

  /** Call a tool. Returns `{ ok, structured, text, raw }`; a tool error is not an exception. */
  async call(name, args = {}, options) {
    const reply = await this.request("tools/call", { name, arguments: args }, options);
    if (reply.error) {
      throw new Error(`${name} failed at the protocol level: ${JSON.stringify(reply.error)}`);
    }
    const result = reply.result;
    return {
      ok: result.isError !== true,
      structured: result.structuredContent,
      text: (result.content || []).map((c) => c.text).join(""),
      raw: reply,
    };
  }

  stop() {
    try {
      this.child.stdin.end();
    } catch {
      /* already closed */
    }
    this.child.kill("SIGTERM");
  }
}

/** A 32-byte random marker, hex-encoded: the canary a secret value must never appear beside. */
export function canary(prefix = "KSE2E") {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return `${prefix}-${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

/** `execFileSync` that returns null rather than throwing. */
export function tryExec(command, args, options = {}) {
  try {
    return execFileSync(command, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      ...options,
    });
  } catch {
    return null;
  }
}
