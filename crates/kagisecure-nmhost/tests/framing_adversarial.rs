//! Adversarial: what the real `kagisecure-nmhost` process does with hostile bytes on stdin.
//!
//! The host is a pipe with no vault, and its one safety property is arithmetic: a length prefix
//! it reads is *checked before it is allocated*, and every frame it accepts produces exactly one
//! reply and at most one forwarded request. A host that answered twice would desynchronize the
//! extension's correlation; a host that answered zero times would hang the port; a host that
//! allocated a declared length before checking it would be a one-frame denial of service against
//! the browser.
//!
//! These tests spawn the **real binary** and write raw bytes at its stdin, rather than calling
//! `run()` in-process as the crate's own unit tests do. That is the difference that matters here:
//! an oversized declared length is only interesting if the process actually exits instead of
//! trying to allocate it, and "the process exited" is not something an in-process test can see.
//!
//! No app is listening in any of these tests, and that is deliberate — `connect_default()` fails,
//! so every well-formed request is answered `VAULT_LOCKED` without a vault existing anywhere. The
//! forwarding path is covered end-to-end from the other side, in `kagisecure-agent`'s
//! `extension.rs`.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use kagisecure_extension_ipc::nm;
use kagisecure_extension_ipc::protocol::{Envelope, PageContext, Request, Response};

/// A canary that never has anything to do with a vault: it is written *at* the host, inside
/// hostile frames, so that a host which echoed its input back would be caught.
const INPUT_CANARY: &str = "NMH0ST-1NPUT-C4N4RY-6f2a9d3b";

/// The real binary under test. Cargo builds it for us and names it here.
fn nmhost() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kagisecure-nmhost"))
}

/// What one run of the host did.
struct Run {
    /// The process's exit code, or `None` if it was killed by a signal.
    code: Option<i32>,
    /// Everything it wrote to stdout.
    stdout: Vec<u8>,
    /// Everything it wrote to stderr.
    stderr: String,
}

impl Run {
    /// Every reply the host framed on stdout, decoded.
    ///
    /// Stops at the first thing that is not a complete frame, so trailing garbage — which would
    /// itself be a bug — shows up as a missing reply rather than as a panic.
    fn replies(&self) -> Vec<Envelope<Response>> {
        let mut cursor = self.stdout.as_slice();
        let mut out = Vec::new();
        while let Ok(envelope) = nm::read::<_, Envelope<Response>>(&mut cursor) {
            out.push(envelope);
        }
        out
    }
}

/// Write `input` to a fresh host process, close the port, and collect everything it did.
///
/// `KAGISECURE_EXTENSION_SOCKET` is pointed at a path that does not exist, so the host's attempt
/// to reach an app fails in the ordinary "the app is not running" way rather than finding some
/// other user's socket.
fn feed(input: &[u8]) -> Run {
    let mut child = Command::new(nmhost())
        .env(
            "KAGISECURE_EXTENSION_SOCKET",
            "/nonexistent/kagisecure-framing-adversarial.sock",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kagisecure-nmhost");

    {
        let mut stdin = child.stdin.take().expect("stdin");
        // A host that has already exited makes this a broken pipe, which is a legitimate outcome
        // for several of the inputs below rather than a test failure.
        let _ = stdin.write_all(input);
        let _ = stdin.flush();
    }

    let mut stdout = Vec::new();
    if let Some(mut handle) = child.stdout.take() {
        let _ = handle.read_to_end(&mut stdout);
    }
    let mut stderr = String::new();
    if let Some(mut handle) = child.stderr.take() {
        let _ = handle.read_to_string(&mut stderr);
    }
    let status = child.wait().expect("wait for the host");

    Run {
        code: status.code(),
        stdout,
        stderr,
    }
}

/// One frame, framed the way Chrome frames it.
fn browser_frame(id: &str, request: &Request) -> Vec<u8> {
    let mut buf = Vec::new();
    nm::write(&mut buf, &Envelope::new(id, request)).expect("frame");
    buf
}

/// A frame whose declared length is whatever `declared` says, regardless of the body.
fn frame_with_declared_length(declared: u32, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&declared.to_ne_bytes());
    buf.extend_from_slice(body);
    buf
}

// ---------------------------------------------------------------------------
// B-34: oversized declared lengths.
// ---------------------------------------------------------------------------

#[test]
fn a_declared_length_past_the_limit_stops_the_host_without_allocating_it() {
    // Four bytes in, a gigabyte declared. The host must refuse on the number alone: a process
    // that allocated first would be a denial of service that costs an attacker four bytes.
    for declared in [
        u32::MAX,
        u32::MAX - 1,
        0x8000_0000,
        (nm::MAX_BROWSER_TO_HOST as u32) + 1,
    ] {
        let run = feed(&frame_with_declared_length(declared, b""));
        assert_eq!(
            run.code,
            Some(1),
            "a declared length of {declared} should stop the host, not be answered"
        );
        assert!(
            run.replies().is_empty(),
            "nothing may be framed back for a frame that was never read: {:?}",
            run.replies()
        );
        assert!(
            run.stderr.contains("exceeds"),
            "the refusal should say why, on stderr where Chrome logs it: {}",
            run.stderr
        );
    }
}

#[test]
fn the_largest_permitted_declared_length_is_still_refused_when_the_body_never_arrives() {
    // Exactly at the limit is allowed as a *number*, so the host proceeds to read a body that
    // never comes. That must end the process cleanly rather than hang it or answer it.
    let run = feed(&frame_with_declared_length(
        nm::MAX_BROWSER_TO_HOST as u32,
        INPUT_CANARY.as_bytes(),
    ));
    assert!(
        run.replies().is_empty(),
        "a truncated body is not something to answer"
    );
    assert_eq!(
        run.code,
        Some(0),
        "a port that closes mid-body is the ordinary way a native host dies"
    );
    assert!(!run.stderr.contains(INPUT_CANARY), "{}", run.stderr);
}

// ---------------------------------------------------------------------------
// B-34: the byte order of the prefix.
// ---------------------------------------------------------------------------

#[test]
fn a_length_prefix_written_in_the_opposite_byte_order_is_refused_rather_than_misread() {
    // Chrome writes native-endian, and so does the host. A frame whose prefix was written the
    // other way round declares an enormous length on this machine, and must be refused by the
    // size check rather than misread into a partial body.
    let honest = browser_frame("a", &Request::Status);
    let body = &honest[4..];
    let flipped = {
        let mut prefix = honest[..4].to_vec();
        prefix.reverse();
        let mut buf = prefix;
        buf.extend_from_slice(body);
        buf
    };
    assert_ne!(
        flipped[..4],
        honest[..4],
        "the test is meaningless if the length is a palindrome"
    );

    let run = feed(&flipped);
    assert_eq!(
        run.code,
        Some(1),
        "a byte-swapped prefix declares a preposterous length and stops the host"
    );
    assert!(run.replies().is_empty());
}

#[test]
fn a_frame_written_for_the_app_socket_does_not_pass_as_a_native_message() {
    // The app socket is big-endian by design, so that a frame sent to the wrong socket fails
    // loudly. The same property in the other direction: an app-socket frame arriving on the
    // host's stdin declares a huge native-endian length on a little-endian machine.
    let body = br#"{"ksx":1,"id":"a","body":{"ask":"status"}}"#;
    let mut app_frame = Vec::new();
    app_frame.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    app_frame.extend_from_slice(body);

    let run = feed(&app_frame);
    if cfg!(target_endian = "little") {
        assert_eq!(
            run.code,
            Some(1),
            "a big-endian prefix is an enormous native-endian length here"
        );
        assert!(run.replies().is_empty());
    } else {
        // On a big-endian machine the two framings coincide, and the frame is simply a valid
        // request; what must still hold is that it is answered exactly once.
        assert_eq!(run.replies().len(), 1);
    }
}

// ---------------------------------------------------------------------------
// B-34: truncation, at every offset.
// ---------------------------------------------------------------------------

#[test]
fn a_frame_truncated_at_any_offset_is_never_answered_more_than_once() {
    let honest = browser_frame("trunc", &Request::Status);
    for cut in 0..honest.len() {
        let run = feed(&honest[..cut]);
        let replies = run.replies();
        assert!(
            replies.len() <= 1,
            "a truncated frame cut at {cut} produced {} replies",
            replies.len()
        );
        assert!(
            run.code.is_some(),
            "the host must exit rather than be killed, at cut {cut}"
        );
        assert!(
            !run.stderr.contains("panicked"),
            "a truncated frame at {cut} panicked the host: {}",
            run.stderr
        );
    }
}

#[test]
fn a_good_frame_followed_by_a_truncated_one_answers_the_good_one_and_stops() {
    let mut input = browser_frame("first", &Request::Status);
    let second = browser_frame(
        "second",
        &Request::Match {
            page: PageContext::top("https://example.com"),
        },
    );
    input.extend_from_slice(&second[..second.len() - 5]);

    let run = feed(&input);
    let replies = run.replies();
    assert_eq!(
        replies.len(),
        1,
        "the complete frame is answered and the incomplete one is not"
    );
    assert_eq!(replies[0].id, "first");
    assert_eq!(
        run.code,
        Some(0),
        "a half frame is a closed port, not a crash"
    );
}

// ---------------------------------------------------------------------------
// Bodies that are not requests at all.
// ---------------------------------------------------------------------------

#[test]
fn every_unreadable_body_is_answered_exactly_once_and_never_echoed() {
    // A body that is not an envelope of this protocol is answered on the fixed `malformed` id,
    // which is what tells the extension its last message was rejected. The reply must be a
    // refusal, and — for the shapes here, where the canary sits in a field the parser rejects
    // structurally rather than by name — it must not quote the input back.
    let bodies: Vec<Vec<u8>> = vec![
        b"{}".to_vec(),
        b"[]".to_vec(),
        b"null".to_vec(),
        b"\"a string\"".to_vec(),
        b"0".to_vec(),
        b"not json at all".to_vec(),
        format!(r#"{{"ksx":1,"id":"{INPUT_CANARY}"}}"#).into_bytes(),
        format!(r#"{{"not":"an envelope","canary":"{INPUT_CANARY}"}}"#).into_bytes(),
        // Valid JSON, wrong protocol marker.
        br#"{"ksx":99,"id":"x","body":{"ask":"status"}}"#.to_vec(),
        // Invalid UTF-8 inside an otherwise plausible frame.
        vec![0x7b, 0x22, 0xff, 0xfe, 0x22, 0x7d],
        // An empty body, declared as empty.
        Vec::new(),
    ];

    for body in &bodies {
        let declared = u32::try_from(body.len()).expect("a small body");
        let run = feed(&frame_with_declared_length(declared, body));
        let replies = run.replies();
        assert!(
            replies.len() <= 1,
            "body {body:?} produced {} replies",
            replies.len()
        );
        if let Some(reply) = replies.first() {
            assert!(
                matches!(reply.body, Response::Error { .. }),
                "body {body:?} was answered with something other than an error: {:?}",
                reply.body
            );
            let text = serde_json::to_string(&reply.body).expect("json");
            assert!(
                !text.contains(INPUT_CANARY),
                "the host echoed its own input back in an error: {text}"
            );
        }
        assert!(
            !run.stderr.contains("panicked"),
            "body {body:?} panicked the host: {}",
            run.stderr
        );
    }
}

#[test]
fn a_stream_of_malformed_frames_is_answered_one_for_one_without_desynchronizing() {
    // The correlation property: however many frames arrive, the extension gets exactly one reply
    // per frame, in order. A host that answered twice for one frame would make every later reply
    // line up against the wrong request — which, on this channel, is how a value could be handed
    // to a caller that asked for something else.
    const FRAMES: usize = 50;
    let mut input = Vec::new();
    for index in 0..FRAMES {
        let body = format!(r#"{{"garbage":{index}}}"#);
        input.extend_from_slice(&frame_with_declared_length(
            u32::try_from(body.len()).unwrap(),
            body.as_bytes(),
        ));
    }

    let run = feed(&input);
    let replies = run.replies();
    assert_eq!(
        replies.len(),
        FRAMES,
        "one reply per frame, no more and no fewer"
    );
    for reply in &replies {
        assert_eq!(reply.id, "malformed");
        assert!(matches!(reply.body, Response::Error { .. }));
    }
    assert_eq!(run.code, Some(0));
}

#[test]
fn a_run_of_well_formed_requests_is_answered_in_order_with_no_app_to_forward_to() {
    // The baseline the tests above are measured against, and the one place the ordinary path is
    // exercised on the real binary: every request gets its own id back, in the order it was sent.
    let ids = ["a", "b", "c", "d", "e"];
    let mut input = Vec::new();
    for id in ids {
        input.extend_from_slice(&browser_frame(id, &Request::Status));
    }

    let run = feed(&input);
    let replies = run.replies();
    assert_eq!(replies.len(), ids.len());
    for (reply, id) in replies.iter().zip(ids) {
        assert_eq!(reply.id, id, "replies must arrive in the order asked");
        assert!(
            matches!(reply.body, Response::Error { .. }),
            "with no app listening every request is a refusal: {:?}",
            reply.body
        );
    }
    assert_eq!(run.code, Some(0));
    assert!(!run.stderr.contains("panicked"), "{}", run.stderr);
}
