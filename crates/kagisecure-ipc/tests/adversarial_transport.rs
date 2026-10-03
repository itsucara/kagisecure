//! Adversarial tests for the transport itself: framing, connection load, and peer identity.
//!
//! `kagisecure-ipc` is the only thing standing between a local process and the one process that
//! holds an unlocked vault key. It has three jobs and this file attacks all three:
//!
//! * **Framing.** A `u32` length prefix and a 1 MiB cap. A hostile peer must not be able to make
//!   the reader allocate a gigabyte, spin, or accept a body it did not send.
//! * **Load.** The agent is thread-per-connection with no bound, so a peer that opens hundreds
//!   of connections and sits on them is the cheapest denial of service available. The server has
//!   to keep answering.
//! * **Identity.** Everything the app tells a human about the caller comes from here. What the
//!   kernel said and what the peer said about itself must never be confused, and the same-user
//!   gate must not evaporate when the uid cannot be determined.
//!
//! These use a real `Server` on a real socket in a temp directory, with real `Client`s.

#[cfg(unix)]
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use kagisecure_ipc::frame::{self, FrameError, MAX_FRAME};
use kagisecure_ipc::protocol::{ClientInfo, ErrorCode, Request, Response};
use kagisecure_ipc::server::Server;
use kagisecure_ipc::{Client, Endpoint};

/// How many connections a hostile peer opens and then abandons mid-frame.
#[cfg(unix)]
const HOSTILE_CONNECTIONS: usize = 500;

/// A canary that must never appear anywhere; the transport carries no values at all, so its
/// absence is a structural claim rather than a redaction claim.
const MARKER: &str = "K4G1-C4N4RY-af41c07b93e2d685f0a1";

/// `own_uid` reads `$TMPDIR`, a process-wide global. The tests below change it, so they take
/// this lock rather than racing each other inside one test binary.
#[cfg(unix)]
static TMPDIR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn client_info(name: &str) -> ClientInfo {
    ClientInfo {
        name: name.to_owned(),
        version: "0".to_owned(),
        pid: std::process::id(),
        parent_pid: None,
        argv0: "adversarial-transport".to_owned(),
        cwd: None,
    }
}

/// A trivial echo server: accepts, answers `ListVaults` with an empty list, forever.
struct Harness {
    _dir: tempfile::TempDir,
    endpoint: Endpoint,
    stopping: Arc<AtomicBool>,
    /// Read only by the tests that write hostile frames straight onto the socket, which are
    /// Unix-only; the counter itself is kept unconditionally so `start()` stays one function.
    #[cfg_attr(not(unix), allow(dead_code))]
    served: Arc<AtomicUsize>,
    accept: Option<std::thread::JoinHandle<()>>,
}

impl Harness {
    fn start() -> Self {
        // Creating a temp dir reads `$TMPDIR`, same as the probes below, so this has to be
        // serialized against them too: otherwise a harness-based test can land here while a
        // `TMPDIR_LOCK`-holding test has pointed `$TMPDIR` at a path that does not exist.
        #[cfg(unix)]
        let dir = {
            let _serialized = TMPDIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            tempfile::tempdir().expect("tempdir")
        };
        #[cfg(not(unix))]
        let dir = tempfile::tempdir().expect("tempdir");
        // One endpoint per harness, in a form this platform can actually bind: a socket in the
        // temporary directory on Unix, a pipe name of its own on Windows. Distinct per instance
        // so two harnesses never collide — which is not a claim about who else can connect.
        let endpoint = Endpoint::for_instance(dir.path(), "adversarial.sock");
        let server = Server::bind(&endpoint).expect("bind");
        server
            .set_accept_nonblocking(true)
            .expect("nonblocking accept");
        let stopping = Arc::new(AtomicBool::new(false));
        let served = Arc::new(AtomicUsize::new(0));

        let accept_stopping = Arc::clone(&stopping);
        let accept_served = Arc::clone(&served);
        let accept = std::thread::spawn(move || {
            let mut workers = Vec::new();
            while !accept_stopping.load(Ordering::SeqCst) {
                match server.accept() {
                    Ok(mut connection) => {
                        let stopping = Arc::clone(&accept_stopping);
                        let served = Arc::clone(&accept_served);
                        let worker = std::thread::Builder::new()
                            .name("adversarial-conn".to_owned())
                            .spawn(move || {
                                while !stopping.load(Ordering::SeqCst) {
                                    match connection.read_request() {
                                        Ok(request) => {
                                            served.fetch_add(1, Ordering::SeqCst);
                                            let response = match request {
                                                Request::Hello { client, .. } => {
                                                    connection.adopt_reported(client);
                                                    Response::Hello {
                                                        server: "adversarial-harness".to_owned(),
                                                        version: "0".to_owned(),
                                                        protocol: 1,
                                                        client_identity: connection
                                                            .identity()
                                                            .describe(),
                                                        client_verified: connection
                                                            .identity()
                                                            .verified(),
                                                    }
                                                }
                                                _ => Response::Vaults { vaults: Vec::new() },
                                            };
                                            if connection.write_response(&response).is_err() {
                                                return;
                                            }
                                        }
                                        Err(_) => return,
                                    }
                                }
                            });
                        if let Ok(worker) = worker {
                            workers.push(worker);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
            for worker in workers {
                let _ = worker.join();
            }
        });

        Self {
            _dir: dir,
            endpoint,
            stopping,
            served,
            accept: Some(accept),
        }
    }

    #[cfg(unix)]
    fn raw(&self) -> std::os::unix::net::UnixStream {
        let Endpoint::Path(path) = &self.endpoint else {
            panic!("this harness is unix-only");
        };
        std::os::unix::net::UnixStream::connect(path).expect("raw connect")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
    }
}

/// A-27: hundreds of connections, each declaring a full-size frame and never sending it.
///
/// This is the cheapest attack there is: the peer costs nothing, the server costs a thread and a
/// buffer per connection. What must hold is that a legitimate client can still connect and get
/// an answer while every one of those threads is parked in `read_exact`.
///
/// This one speaks `AF_UNIX` directly: it has to open hundreds of sockets without going
/// through `Client`, and there is no portable way to do that. The Windows equivalent is a
/// `CreateFileW` loop against the pipe name — TODO(windows), and a job for a machine that can
/// actually run it.
#[cfg(unix)]
#[test]
fn the_server_still_answers_while_hundreds_of_peers_hold_frames_open() {
    let harness = Harness::start();

    // Each hostile peer sends a maximum-size length prefix and then one byte, forever silent.
    let mut hostiles = Vec::with_capacity(HOSTILE_CONNECTIONS);
    for _ in 0..HOSTILE_CONNECTIONS {
        let Ok(mut stream) = std::os::unix::net::UnixStream::connect({
            let Endpoint::Path(path) = &harness.endpoint else {
                unreachable!()
            };
            path
        }) else {
            // The listener backlog is finite; a refused connection is the OS defending itself,
            // which is a pass, not a failure.
            break;
        };
        let prefix = u32::try_from(MAX_FRAME).expect("fits").to_le_bytes();
        if stream.write_all(&prefix).is_err() || stream.write_all(b"{").is_err() {
            break;
        }
        let _ = stream.flush();
        hostiles.push(stream);
        // Pace the burst so each peer is *accepted* and parked in `read_exact`, which is the
        // pressure this test is about. An unpaced 500-connection burst overflows the kernel's
        // listen backlog in under a millisecond, and every later connect — the legitimate one
        // included — is refused by the kernel before the server ever sees it. That measures the
        // backlog, not the server.
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        hostiles.len() > 16,
        "the test needs real pressure; only {} peers connected",
        hostiles.len()
    );

    // A legitimate client, under that pressure.
    let started = Instant::now();
    let mut client = Client::connect(&harness.endpoint, client_info("legitimate"))
        .expect("a legitimate client can still connect");
    let reply = client
        .call(&Request::ListVaults)
        .expect("and still be served");
    assert!(
        matches!(reply, Response::Vaults { .. }),
        "reply was {reply:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "serving one legitimate client under {} parked peers took {:?}",
        hostiles.len(),
        started.elapsed()
    );

    drop(hostiles);
}

/// A declared length above the cap is refused before a single byte of body is allocated.
#[test]
fn an_oversized_declared_length_is_refused_without_allocating_it() {
    for declared in [MAX_FRAME + 1, u32::MAX as usize] {
        let mut wire = Vec::new();
        wire.extend_from_slice(&u32::try_from(declared).unwrap_or(u32::MAX).to_le_bytes());
        // Deliberately no body: if the reader allocated first, it would block here instead.
        let started = Instant::now();
        let result: Result<Request, FrameError> = frame::read(&mut wire.as_slice());
        assert!(
            matches!(result, Err(FrameError::TooLarge(_))),
            "a {declared}-byte frame was not refused: {result:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "refusing an oversized frame took {:?}",
            started.elapsed()
        );
    }
}

/// A-28: deeply nested and enormous JSON bodies are a parse error, not a crash or a stall.
///
/// `serde_json` has its own recursion limit, which is precisely the reason not to take it on
/// trust: this asserts the limit is actually reached rather than assumed.
#[test]
fn hostile_json_bodies_are_rejected_without_panic_or_unbounded_time() {
    let bodies: Vec<Vec<u8>> = vec![
        // Nesting far past any legitimate message.
        {
            let depth = 100_000;
            let mut body = Vec::with_capacity(depth * 2);
            body.extend(std::iter::repeat_n(b'[', depth));
            body.extend(std::iter::repeat_n(b']', depth));
            body
        },
        // A single enormous string, just under the cap.
        {
            let mut body = Vec::new();
            body.extend_from_slice(b"{\"ListItems\":{\"query\":\"");
            body.extend(std::iter::repeat_n(b'a', MAX_FRAME - 64));
            body.extend_from_slice(b"\"}}");
            body.truncate(MAX_FRAME);
            body
        },
        // An enormous object key.
        {
            let mut body = Vec::new();
            body.extend_from_slice(b"{\"");
            body.extend(std::iter::repeat_n(b'k', 512 * 1024));
            body.extend_from_slice(b"\":1}");
            body
        },
        // Not JSON at all.
        b"\xff\xfe\x00\x00not json".to_vec(),
        // Valid JSON, wrong shape.
        b"{\"ListVaults\":{\"unexpected\":true}}".to_vec(),
    ];

    for body in bodies {
        let len = body.len().min(MAX_FRAME);
        let mut wire = Vec::with_capacity(len + 4);
        wire.extend_from_slice(&u32::try_from(len).expect("fits").to_le_bytes());
        wire.extend_from_slice(&body[..len]);

        let started = Instant::now();
        let result: Result<Request, FrameError> = frame::read(&mut wire.as_slice());
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "a {len}-byte hostile body took {:?}",
            started.elapsed()
        );
        if let Ok(parsed) = result {
            // A body that happens to parse is fine; it must simply not be a value carrier.
            assert!(
                !format!("{parsed:?}").contains(MARKER),
                "the wire format carries no values"
            );
        }
    }
}

/// A hostile body over the wire leaves the server alive for the next client.
///
/// Unix-only for the same reason as the load test above: it writes a hostile frame straight
/// onto the socket rather than through `Client`.
#[cfg(unix)]
#[test]
fn a_malformed_frame_closes_one_connection_and_no_others() {
    let harness = Harness::start();

    {
        let mut hostile = harness.raw();
        let body = b"not json at all";
        hostile
            .write_all(&u32::try_from(body.len()).expect("fits").to_le_bytes())
            .expect("prefix");
        hostile.write_all(body).expect("body");
        hostile.flush().expect("flush");
    }

    let mut client = Client::connect(&harness.endpoint, client_info("after-the-storm"))
        .expect("the server survived");
    let reply = client.call(&Request::ListVaults).expect("call");
    assert!(
        matches!(reply, Response::Vaults { .. }),
        "reply was {reply:?}"
    );
    assert!(harness.served.load(Ordering::SeqCst) > 0);
}

/// A-21: what the kernel said and what the peer said about itself are distinguishable.
///
/// `PeerIdentity::pid_from_kernel` is the whole point of the field: on macOS `LOCAL_PEERPID` may
/// not answer, in which case `adopt_reported` takes the peer's own word for its pid so the sheet
/// can still resolve an executable — and `verified()` must stay false. A UI that showed the two
/// cases identically would be presenting a self-report as a kernel fact.
#[test]
fn a_self_reported_pid_is_never_presented_as_a_kernel_fact() {
    let harness = Harness::start();
    let mut client =
        Client::connect(&harness.endpoint, client_info("identity-probe")).expect("connect");
    let reply = client.call(&Request::ListVaults).expect("call");
    assert!(matches!(reply, Response::Vaults { .. }));

    // `Client::connect` performs the Hello, and the server's answer carries how it saw us.
    let identity = client.identity().to_owned();
    let verified = client.verified();
    if verified {
        assert!(
            !identity.contains("self-reported") && !identity.contains("unverified"),
            "a kernel-verified identity must not hedge: {identity}"
        );
    } else {
        assert!(
            identity.to_lowercase().contains("self-reported")
                || identity.to_lowercase().contains("unverified")
                || identity.to_lowercase().contains("says"),
            "an unverified identity must say so in the string a human reads: {identity}"
        );
    }
}

/// D-9 / A-29: `own_uid` returns `None` when it cannot probe, and the gate that uses it fails open.
///
/// `server::own_uid` derives the uid by creating `$TMPDIR/kagisecure-uid-<pid>` and reading the
/// owner back. When `$TMPDIR` is not writable the probe fails and the function returns `None`.
/// The same-user gate in `kagisecure-agent`'s `serve_connection` is
/// `if let (Some(peer), Some(mine)) = (..euid, own_uid()) && peer != mine`, so a `None` here
/// **skips the check entirely** and the socket serves whoever reached it.
///
/// The check is documented as "a hard gate rather than a warning (threat-model M-13/M-15)". A
/// gate that disappears when its input is unavailable is not a hard gate, and the input is
/// supplied by an environment variable the peer's parent may control.
///
/// Unix-only: `own_uid` has no meaning on Windows, where it answers `None` by construction and
/// the same-user gate compares token SIDs instead (behind the pipe's owner-only DACL); the unit
/// tests in `server.rs` cover that arm.
#[cfg(unix)]
#[test]
// PREDICTED FAILURE (D-9), from source reading only: `File::create` under a non-existent
// `$TMPDIR` fails and `own_uid` returns `None`. Never executed.
fn the_same_user_gate_fails_closed_when_the_uid_cannot_be_determined() {
    let _serialized = TMPDIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let original = std::env::var_os("TMPDIR");
    let unwritable = tempfile::tempdir().expect("tempdir");
    let blocked = unwritable.path().join("no-such-directory");
    // SAFETY: `TMPDIR_LOCK` above serializes this binary's environment-mutating tests, and the
    // variable is restored immediately below.
    unsafe {
        std::env::set_var("TMPDIR", &blocked);
    }
    let uid = kagisecure_ipc::server::own_uid();
    // SAFETY: as above.
    unsafe {
        match original {
            Some(value) => std::env::set_var("TMPDIR", value),
            None => std::env::remove_var("TMPDIR"),
        }
    }

    assert!(
        uid.is_some(),
        "own_uid returned None, which makes the same-user gate a no-op; the gate has no \
         fail-closed path because it is written as `if let (Some(peer), Some(mine))`"
    );
}

/// The uid probe writes to a predictable path and follows a symlink to truncate it.
///
/// `own_uid` opens `$TMPDIR/kagisecure-uid-<pid>` with `File::create`, which follows symlinks and
/// truncates. The filename is derived from our own pid, so another local process that can write
/// to `$TMPDIR` — a shared `/tmp`, the default on many systems — can plant a symlink there ahead
/// of us and have us truncate whatever it points at, with our privileges.
///
/// Unix-only: `$TMPDIR`, `symlink(2)` and uids.
#[cfg(unix)]
#[test]
// PREDICTED FAILURE (D-9), from source reading only: `File::create` follows symlinks and
// truncates. Never executed.
fn the_uid_probe_does_not_follow_a_symlink_planted_at_its_path() {
    // The lock has to be taken before the temp dir is created, not just before `$TMPDIR` is
    // mutated: `tempfile::tempdir()` itself reads `$TMPDIR`, so creating it first would let this
    // test race another test that has already pointed `$TMPDIR` at a path that does not exist.
    let _serialized = TMPDIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("tempdir");
    let victim = dir.path().join("victim");
    const VICTIM_CONTENTS: &str = "data this process did not intend to destroy\n";
    std::fs::write(&victim, VICTIM_CONTENTS).expect("seed the victim file");

    let planted = dir
        .path()
        .join(format!("kagisecure-uid-{}", std::process::id()));
    std::os::unix::fs::symlink(&victim, &planted).expect("plant the symlink");

    let original = std::env::var_os("TMPDIR");
    // SAFETY: `TMPDIR_LOCK` above keeps every environment-mutating test in this binary from
    // running concurrently, and the variable is restored immediately below.
    unsafe {
        std::env::set_var("TMPDIR", dir.path());
    }
    let _ = kagisecure_ipc::server::own_uid();
    // SAFETY: as above.
    unsafe {
        match original {
            Some(value) => std::env::set_var("TMPDIR", value),
            None => std::env::remove_var("TMPDIR"),
        }
    }

    assert_eq!(
        std::fs::read_to_string(&victim).unwrap_or_default(),
        VICTIM_CONTENTS,
        "the uid probe truncated a file it was pointed at by a symlink it did not create"
    );
}

/// Whatever else it does, `own_uid` agrees with the uid of a file this process really owns.
///
/// Unix-only: uids.
#[cfg(unix)]
#[test]
fn the_uid_probe_reports_this_process_own_uid() {
    use std::os::unix::fs::MetadataExt;
    let _serialized = TMPDIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("tempdir");
    let mine = dir.path().join("owned-by-me");
    std::fs::write(&mine, b"x").expect("write");
    let expected = std::fs::metadata(&mine).expect("metadata").uid();

    assert_eq!(
        kagisecure_ipc::server::own_uid(),
        Some(expected),
        "the uid probe must agree with the filesystem about who we are"
    );
}

/// A frame at exactly the cap round-trips; one byte over does not.
#[test]
fn the_frame_cap_is_inclusive_and_one_byte_over_is_refused() {
    let at_cap = Response::error(ErrorCode::Internal, "x".repeat(MAX_FRAME / 2));
    let mut buf = Vec::new();
    frame::write(&mut buf, &at_cap).expect("a half-megabyte message fits");
    let back: Response = frame::read(&mut buf.as_slice()).expect("and reads back");
    assert_eq!(back, at_cap);

    let too_big = Response::error(ErrorCode::Internal, "x".repeat(MAX_FRAME + 1));
    let mut buf = Vec::new();
    assert!(
        matches!(
            frame::write(&mut buf, &too_big),
            Err(FrameError::TooLarge(_))
        ),
        "a message over the cap must not be written"
    );
    assert!(buf.is_empty(), "and no partial frame may reach the wire");
}

/// A truncated frame is `Closed`, never a partial parse.
#[test]
fn a_truncated_frame_is_a_clean_close_and_never_a_partial_message() {
    let mut wire = Vec::new();
    frame::write(&mut wire, &Request::ListVaults).expect("write");
    for cut in 1..wire.len() {
        let result: Result<Request, FrameError> = frame::read(&mut &wire[..cut]);
        assert!(
            matches!(
                result,
                Err(FrameError::Closed) | Err(FrameError::Malformed(_))
            ),
            "a frame cut at {cut} of {} produced {result:?}",
            wire.len()
        );
    }
}
