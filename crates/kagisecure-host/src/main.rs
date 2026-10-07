//! `kagisecure-host`: see the library's documentation and ADR-0043.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use kagisecure_host::engine::Engine;
use kagisecure_host::identity::{self, KeySource};
use kagisecure_host::store::{DEFAULT_STATE_DIR, Store};

/// The systemd unit, for `kagisecure-host systemd-unit`.
const UNIT: &str = include_str!("../systemd/kagisecure-host.service");

/// The exit code for a refusal: `EX_TEMPFAIL`'s neighbour `EX_NOPERM`.
const REFUSED: u8 = 77;

#[derive(Debug, Parser)]
#[command(
    name = "kagisecure-host",
    version,
    about = "kagisecure on a headless host (ADR-0043)"
)]
struct Cli {
    /// The state directory: the host key, the bundle, uses, suspensions and the audit log.
    #[arg(long, global = true, env = "KAGISECURE_HOST_STATE", default_value = DEFAULT_STATE_DIR)]
    state: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create this host's key pair (once) and record the owner whose bundles it accepts.
    Init {
        /// The owner's public key, as `kagisecure host-bundle owner-key` prints it on the Mac.
        #[arg(long)]
        owner: Option<String>,
    },
    /// Print this host's public key and fingerprint, for `kagisecure host-bundle export`.
    Show,
    /// Verify a bundle from the Mac and make it this host's.
    Import {
        /// The bundle file.
        bundle: PathBuf,
    },
    /// List the grants this host holds, their uses and suspensions.
    Status,
    /// Print the last audit entries.
    Audit {
        /// How many.
        #[arg(long, default_value_t = 20)]
        last: usize,
    },
    /// Serve the host socket (what the systemd unit runs).
    #[cfg(unix)]
    Serve {
        /// The socket path.
        #[arg(long, env = "KAGISECURE_HOST_SOCKET", default_value = kagisecure_host::server::DEFAULT_SOCKET)]
        socket: PathBuf,
    },
    /// Ask the host to run a granted command: `request deploy-staging -- /path/deploy staging <sha>`.
    #[cfg(unix)]
    Request {
        /// The socket path.
        #[arg(long, env = "KAGISECURE_HOST_SOCKET", default_value = kagisecure_host::server::DEFAULT_SOCKET)]
        socket: PathBuf,
        /// The grant's name.
        grant: String,
        /// The command line, the executable first, exactly as the grant names it.
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Print the systemd unit template.
    SystemdUnit,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("kagisecure-host: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let store = Store::new(&cli.state);
    match cli.command {
        Command::Init { owner } => {
            store.ensure_dir()?;
            let created = match identity::load(store.dir()) {
                Ok(_) => false,
                Err(_) if !store.dir().join(identity::KEY_FILE).exists() => {
                    identity::create(store.dir())?;
                    true
                }
                Err(e) => return Err(e.into()),
            };
            if let Some(owner) = owner {
                let owner = identity::public_from_text(&owner).context("--owner")?;
                identity::trust_owner(store.dir(), &owner)?;
                println!(
                    "Trusting bundles signed by the owner device {}",
                    owner.fingerprint()
                );
            }
            if created {
                println!(
                    "Created this host's key in {} (0600).\n\
                     Anything that can read that file — this service account, or root — can open \
                     every bundle made for this host and so holds every value in it.",
                    store.dir().join(identity::KEY_FILE).display()
                );
            }
            show(&store)?;
        }
        Command::Show => show(&store)?,
        Command::Import { bundle } => {
            let bytes =
                std::fs::read(&bundle).with_context(|| format!("reading {}", bundle.display()))?;
            let opened = Engine::new(store).import(&bytes)?;
            println!(
                "Imported bundle {} for host {:?}: {} grant(s).",
                opened.sequence,
                opened.contents.host_name,
                opened.contents.grants.len()
            );
            for g in &opened.contents.grants {
                println!("  {}  {}", g.name, g.command_line());
            }
        }
        Command::Status => {
            let engine = Engine::new(store);
            let opened = engine.current()?;
            let state = engine.store().state()?;
            println!(
                "Bundle {} for host {:?}",
                opened.sequence, opened.contents.host_name
            );
            for g in &opened.contents.grants {
                let gs = state.grants.get(&g.name).cloned().unwrap_or_default();
                println!("{}", g.name);
                println!("  command   {}", g.command_line());
                println!("  in        {}", g.working_dir);
                println!(
                    "  as        {}",
                    g.run_as.as_deref().unwrap_or("(host account)")
                );
                println!(
                    "  stdin     {} from {:?}",
                    g.variables.join(", "),
                    g.environment
                );
                println!("  uses      {}/{}", gs.uses, g.limits.total_uses);
                println!("  expires   {} (unix)", g.limits.expires_at);
                match gs.suspended {
                    Some(s) => println!("  SUSPENDED {} at {}", s.reason, s.at),
                    None if !g.pin_holds() => {
                        println!("  pin       CHANGED (next request suspends)")
                    }
                    None => println!("  pin       holds"),
                }
            }
        }
        Command::Audit { last } => {
            let lines = store.audit_lines()?;
            for line in &lines[lines.len().saturating_sub(last)..] {
                println!("{line}");
            }
        }
        #[cfg(unix)]
        Command::Serve { socket } => {
            let engine = std::sync::Arc::new(Engine::new(store));
            engine.current().context("refusing to serve")?;
            eprintln!("kagisecure-host: serving {}", socket.display());
            kagisecure_host::server::serve(engine, &socket)?;
        }
        #[cfg(unix)]
        Command::Request {
            socket,
            grant,
            argv,
        } => {
            use kagisecure_host::protocol::{Request, Response};
            use std::io::Write as _;
            let cwd = std::env::current_dir().context("reading the current directory")?;
            let request = Request {
                grant,
                argv,
                cwd: cwd.to_string_lossy().into_owned(),
            };
            match kagisecure_host::client::request(&socket, &request)? {
                Response::Ran {
                    exit_code,
                    timed_out,
                    stdout,
                    stderr,
                } => {
                    let _ = std::io::stdout().write_all(stdout.as_bytes());
                    let _ = std::io::stderr().write_all(stderr.as_bytes());
                    if timed_out {
                        eprintln!(
                            "kagisecure-host: the command reached its deadline and was ended"
                        );
                    }
                    let code = exit_code.and_then(|c| u8::try_from(c).ok()).unwrap_or(1);
                    return Ok(ExitCode::from(code));
                }
                Response::Refused { reason, message } => {
                    eprintln!("kagisecure-host: refused ({reason}): {message}");
                    return Ok(ExitCode::from(REFUSED));
                }
            }
        }
        Command::SystemdUnit => print!("{UNIT}"),
    }
    Ok(ExitCode::SUCCESS)
}

fn show(store: &Store) -> Result<()> {
    let (host, source) = identity::load(store.dir())?;
    println!("Host key   {}", identity::public_to_text(host.public()));
    println!("Fingerprint {}", host.public().fingerprint());
    match source {
        KeySource::Credential(p) => println!("Key from   systemd credential {}", p.display()),
        KeySource::File(p) => println!("Key from   file {} (0600)", p.display()),
    }
    match identity::owner(store.dir()) {
        Ok(owner) => println!("Owner      {}", owner.fingerprint()),
        Err(_) => println!("Owner      (none yet: `kagisecure-host init --owner <key>`)"),
    }
    Ok(())
}
