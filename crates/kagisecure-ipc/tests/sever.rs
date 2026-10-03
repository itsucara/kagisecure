//! What severing an accepted connection does to a reply that is still being written (Unix).
//!
//! A stop denies every queued approval and then severs every connection, so a serving thread can
//! be writing the denial at the moment of the sever. The reply must still reach the peer, the
//! parked read must still end, and — in a host that has not ignored `SIGPIPE`, which is what the
//! macOS app is — a write to a peer that has gone must be an error, not a signal.
#![cfg(unix)]

use std::io::{Read as _, Write as _};

use interprocess::local_socket::{GenericFilePath, ListenerOptions, Stream, prelude::*};
use kagisecure_ipc::sever::Severer;

fn pair(dir: &std::path::Path) -> (Stream, Stream) {
    let path = dir.join("s.sock");
    let listener = ListenerOptions::new()
        .name(path.as_path().to_fs_name::<GenericFilePath>().unwrap())
        .create_sync()
        .unwrap();
    let client = Stream::connect(path.as_path().to_fs_name::<GenericFilePath>().unwrap()).unwrap();
    let server = listener.accept().unwrap();
    (server, client)
}

#[test]
fn a_reply_written_after_the_sever_still_reaches_the_peer_and_the_read_ends() {
    let dir = tempfile::tempdir().unwrap();
    let (mut server, mut client) = pair(dir.path());
    let severer = Severer::for_stream(&server).unwrap();

    severer.sever();

    // The serving thread's parked read ends...
    let mut buf = [0u8; 8];
    assert_eq!(
        server.read(&mut buf).unwrap(),
        0,
        "a severed read is end-of-stream"
    );
    // ...and the denial it was about to send still goes out.
    server.write_all(b"USER_DENIED").unwrap();
    drop(server);
    drop(severer);

    let mut received = Vec::new();
    client.read_to_end(&mut received).unwrap();
    assert_eq!(received, b"USER_DENIED");
}

#[test]
fn writing_to_a_peer_that_has_gone_is_an_error_not_a_signal() {
    // If this raised SIGPIPE the test binary would die here: cargo's test harness is a Rust
    // binary, whose runtime ignores the signal, so restore the default first — the state the
    // macOS app, which links this library, runs in.
    // SAFETY: resetting one signal's disposition to its default, before any thread of this test
    // could be relying on the old one; `signal` keeps no pointer.
    unsafe {
        libc_signal_default_sigpipe();
    }
    let dir = tempfile::tempdir().unwrap();
    let (mut server, client) = pair(dir.path());
    let _severer = Severer::for_stream(&server).unwrap();
    drop(client);

    let mut failed = false;
    for _ in 0..64 {
        if server.write_all(&[0u8; 4096]).is_err() {
            failed = true;
            break;
        }
    }
    assert!(failed, "writing to a closed peer must fail");
}

#[cfg(target_vendor = "apple")]
unsafe fn libc_signal_default_sigpipe() {
    unsafe extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    const SIGPIPE: i32 = 13;
    const SIG_DFL: usize = 0;
    // SAFETY: forwarded to the caller.
    unsafe {
        signal(SIGPIPE, SIG_DFL);
    }
}

#[cfg(not(target_vendor = "apple"))]
unsafe fn libc_signal_default_sigpipe() {
    // Only Apple platforms have `SO_NOSIGPIPE`; elsewhere the library relies on its host.
}
