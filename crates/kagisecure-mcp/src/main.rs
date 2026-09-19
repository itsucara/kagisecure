//! `kagisecure-mcp` — the stdio MCP sidecar.
//!
//! Spawned by an MCP client (Claude Code, Claude Desktop, Codex CLI, Cursor) as a child process.
//! It holds no key material, cannot open a vault file, and has no code path that decrypts
//! anything: every meaningful request goes over local IPC to the process that owns the unlocked
//! vault, and that process is the one that shows the approval and performs the injection
//! (architecture.md §2.2).
//!
//! # stdout belongs to the protocol
//!
//! stdout is the MCP transport. Nothing in this binary writes to it except `rmcp`. Diagnostics go
//! to stderr, where the client's logs pick them up. The canary test asserts the stronger version
//! of this: a marker seeded as a secret value never appears in any byte written to stdout.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod server;

use rmcp::ServiceExt;
use rmcp::transport::stdio;

use server::Kagisecure;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `--version` / `--help` without pulling in an argument parser: this binary takes no
    // arguments, and an MCP client that passes one should be told so on stderr rather than
    // having it silently ignored.
    let mut args = std::env::args().skip(1);
    if let Some(arg) = args.next() {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("kagisecure-mcp {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => {
                eprintln!("kagisecure-mcp: unexpected argument {other:?}");
                print_help();
                std::process::exit(2);
            }
        }
    }

    eprintln!(
        "kagisecure-mcp {} starting on stdio. No secret value is returned by any tool.",
        env!("CARGO_PKG_VERSION")
    );

    let service = Kagisecure::new().serve(stdio()).await.inspect_err(|e| {
        eprintln!("kagisecure-mcp: could not start on stdio: {e}");
    })?;
    service.waiting().await?;
    Ok(())
}

fn print_help() {
    // Intentionally on stderr for the error path and stdout only for an explicit `--help`, where
    // no MCP session exists yet.
    println!(
        "kagisecure-mcp — the kagisecure MCP sidecar.\n\
         \n\
         It speaks MCP over stdio and takes no arguments. An MCP client spawns it; you do not\n\
         normally run it yourself. It needs the process that owns the unlocked vault to be\n\
         running — in this milestone, `kagisecure daemon`.\n\
         \n\
         Register it with:\n\
         \n\
         \x20 kagisecure mcp install claude-code\n\
         \x20 kagisecure mcp install claude-desktop --write\n\
         \x20 kagisecure mcp install codex --write\n\
         \x20 kagisecure mcp install cursor --write\n\
         \n\
         Environment:\n\
         \x20 KAGISECURE_SOCKET   talk to a daemon on this socket instead of the default\n"
    );
}
