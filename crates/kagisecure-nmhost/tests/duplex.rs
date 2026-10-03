//! The real `kagisecure-nmhost` process between a stand-in browser and a stand-in app that speaks
//! first (ADR-0036 §3.1).
//!
//! `framing_adversarial.rs` feeds the host hostile bytes from the browser's side with no app
//! listening at all. These tests put something on the other end of the socket: a plain Unix
//! socket in a temporary directory, written to frame by frame, so the app can send exactly what a
//! test needs — a push nobody asked for, a frame that is not one, a connection closed under the
//! host — without a vault, an agent or a peer check anywhere in the picture.
//!
//! What they hold the host to:
//!
//! * a push reaches the browser as it arrives, not when the next reply happens to be read, in a
//!   frame the host built — `{"ksx":1,"push":{…}}` and nothing else;
//! * an app frame that is neither a push nor a reply is dropped, and none of its bytes reach the
//!   browser;
//! * pushes change nothing about requests: every one is answered exactly once, in order, with its
//!   own reply;
//! * the browser closing the port still ends the process while pushes are flowing;
//! * a reconnect replays the extension's `Hello` before anything else, and the app's answer to
//!   the replay is not passed to a browser that never asked for it.
//!
//! Unix only: on Windows the host forwards no pushes (see the crate documentation).

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kagisecure_extension_ipc::protocol::{
    Capability, Envelope, ErrorCode, PageContext, Push, PushEnvelope, Request, Response,
};
use kagisecure_extension_ipc::{PINNED_EXTENSION_IDS, frame, nm};

/// How long any one step may take before the test calls the host stuck.
const PATIENCE: Duration = Duration::from_secs(30);

/// Written *by the app* into frames the host must drop or re-encode, so a host that copied app
/// bytes onto stdout would be caught.
const APP_CANARY: &str = "NMH0ST-4PP-FR4ME-C4N4RY-b71e04";

fn nmhost() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kagisecure-nmhost"))
}

// ---------------------------------------------------------------------------
// The stand-in app.
// ---------------------------------------------------------------------------

/// A socket where the app's extension listener would be.
struct App {
    _dir: tempfile::TempDir,
    path: PathBuf,
    listener: UnixListener,
}

impl App {
    fn bind() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("extension.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        listener.set_nonblocking(true).expect("nonblocking accept");
        Self {
            _dir: dir,
            path,
            listener,
        }
    }

    /// The next connection from the host, or a panic if none comes.
    fn accept(&self) -> AppConnection {
        let deadline = Instant::now() + PATIENCE;
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    // An accepted socket inherits the listener's non-blocking flag on some
                    // platforms; the app side of these tests reads and writes blocking.
                    stream.set_nonblocking(false).expect("blocking");
                    stream
                        .set_read_timeout(Some(PATIENCE))
                        .expect("read timeout");
                    let writer = stream.try_clone().expect("clone");
                    return AppConnection {
                        reader: stream,
                        writer: Arc::new(Mutex::new(writer)),
                    };
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "the host never connected");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept: {e}"),
            }
        }
    }
}

/// One accepted connection, written whole frames at a time so two threads can share it.
struct AppConnection {
    reader: UnixStream,
    writer: Arc<Mutex<UnixStream>>,
}

impl AppConnection {
    fn read_request(&mut self) -> Envelope<Request> {
        frame::read(&mut self.reader).expect("the host forwards a well-formed request")
    }

    fn reply(&self, id: &str, response: &Response) {
        let mut writer = self.writer.lock().unwrap();
        frame::write(&mut *writer, &Envelope::new(id, response)).expect("write reply");
    }

    /// `false` once the host has gone.
    fn push(&self, push: Push) -> bool {
        let mut writer = self.writer.lock().unwrap();
        frame::write(&mut *writer, &PushEnvelope::new(push)).is_ok()
    }

    /// A frame of the app socket's shape carrying whatever `body` is.
    fn raw(&self, body: &[u8]) {
        let mut writer = self.writer.lock().unwrap();
        let len = u32::try_from(body.len()).expect("small");
        writer.write_all(&len.to_be_bytes()).expect("prefix");
        writer.write_all(body).expect("body");
        writer.flush().expect("flush");
    }
}

fn welcome() -> Response {
    Response::Welcome {
        protocol_version: kagisecure_extension_ipc::PROTOCOL_VERSION,
        app_version: "0.0.0-test".to_owned(),
        unlocked: true,
        host_evidence: vec![],
    }
}

fn hello() -> Request {
    Request::Hello {
        extension_id: PINNED_EXTENSION_IDS[0].to_owned(),
        browser: "chrome".to_owned(),
        extension_version: "0.1.0".to_owned(),
        protocol_version: kagisecure_extension_ipc::PROTOCOL_VERSION,
        capabilities: vec![Capability::AgentFill],
    }
}

fn locate(probe_id: &str) -> Push {
    Push::Locate {
        probe_id: probe_id.to_owned(),
        origin: None,
    }
}

// ---------------------------------------------------------------------------
// The stand-in browser.
// ---------------------------------------------------------------------------

/// What the host wrote to stdout, one frame at a time.
#[derive(Debug)]
enum Frame {
    Reply(Envelope<Response>),
    Push(Push),
}

/// Decode one stdout frame, insisting it is exactly a reply or exactly a push.
fn parse(bytes: &[u8]) -> Frame {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).expect("every frame on stdout is JSON");
    let mut keys: Vec<&str> = value
        .as_object()
        .expect("every frame is an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    match keys.as_slice() {
        ["ksx", "push"] => {
            let envelope: PushEnvelope =
                serde_json::from_value(value).expect("a push frame parses as a push");
            Frame::Push(envelope.push)
        }
        ["body", "id", "ksx"] => {
            Frame::Reply(serde_json::from_value(value).expect("a reply frame parses as a reply"))
        }
        other => {
            panic!("a frame that is neither a reply nor a push reached the browser: {other:?}")
        }
    }
}

/// Chrome, as far as the host can tell: its stdin, and its stdout read on a thread of its own so
/// that a test waits on it with a deadline rather than forever.
struct Browser {
    child: Child,
    stdin: Option<ChildStdin>,
    frames: Receiver<Vec<u8>>,
    /// Every byte the host wrote to stdout, for the canary sweep.
    seen: Arc<Mutex<Vec<u8>>>,
}

impl Drop for Browser {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Browser {
    fn launch(app: &App) -> Self {
        let (child, stdout) = spawn(app);
        let mut browser = Self::new(child);
        let (tx, rx) = channel();
        let seen = Arc::clone(&browser.seen);
        std::thread::spawn(move || read_frames(stdout, &tx, &seen));
        browser.frames = rx;
        browser
    }

    fn new(mut child: Child) -> Self {
        let stdin = child.stdin.take();
        Self {
            child,
            stdin,
            frames: channel().1,
            seen: Arc::default(),
        }
    }

    fn send(&mut self, id: &str, request: &Request) {
        let stdin = self.stdin.as_mut().expect("the port is open");
        nm::write(stdin, &Envelope::new(id, request)).expect("write native message");
    }

    fn next(&self) -> Frame {
        let bytes = self
            .frames
            .recv_timeout(PATIENCE)
            .expect("the host wrote nothing in time");
        parse(&bytes)
    }

    fn next_reply(&self) -> Envelope<Response> {
        match self.next() {
            Frame::Reply(reply) => reply,
            Frame::Push(push) => panic!("expected a reply, got the push {push:?}"),
        }
    }

    fn next_push(&self) -> Push {
        match self.next() {
            Frame::Push(push) => push,
            Frame::Reply(reply) => panic!("expected a push, got the reply {reply:?}"),
        }
    }

    /// Read until the reply with `id`, returning it and every push that arrived before it.
    ///
    /// A push and a reply are written by two threads, so a push the app sent after a reply may
    /// reach stdout before it: the two directions are ordered each within itself, not against
    /// each other.
    fn reply_among_pushes(&self, id: &str) -> (Envelope<Response>, Vec<Push>) {
        let mut pushes = Vec::new();
        loop {
            match self.next() {
                Frame::Push(push) => pushes.push(push),
                Frame::Reply(reply) => {
                    assert_eq!(reply.id, id, "the next reply is the one asked for");
                    return (reply, pushes);
                }
            }
        }
    }

    /// Close the port, wait for the host, and return every frame it wrote after the ones already
    /// read, and its stderr.
    fn close(mut self) -> (Vec<Frame>, String, Vec<u8>) {
        drop(self.stdin.take());
        let status = wait_for_exit(&mut self.child);
        assert!(
            status.success(),
            "a closed port is a clean exit, got {status}"
        );
        let rest = self.frames.iter().map(|bytes| parse(&bytes)).collect();
        let mut stderr = String::new();
        if let Some(mut handle) = self.child.stderr.take() {
            let _ = handle.read_to_string(&mut stderr);
        }
        let seen = self.seen.lock().unwrap().clone();
        (rest, stderr, seen)
    }
}

fn spawn(app: &App) -> (Child, ChildStdout) {
    let mut child = Command::new(nmhost())
        .arg(format!("chrome-extension://{}/", PINNED_EXTENSION_IDS[0]))
        .arg("com.kagisecure.nmhost")
        .env("KAGISECURE_EXTENSION_SOCKET", &app.path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kagisecure-nmhost");
    let stdout = child.stdout.take().expect("stdout");
    (child, stdout)
}

fn read_frames(mut stdout: ChildStdout, to: &Sender<Vec<u8>>, seen: &Mutex<Vec<u8>>) {
    while let Ok(bytes) = nm::read_bytes(&mut stdout) {
        seen.lock().unwrap().extend_from_slice(&bytes);
        if to.send(bytes).is_err() {
            return;
        }
    }
}

fn wait_for_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + PATIENCE;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "the host was still running {PATIENCE:?} after the browser closed its stdin"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_welcome(reply: &Envelope<Response>, id: &str) {
    assert_eq!(reply.id, id);
    assert!(
        matches!(reply.body, Response::Welcome { .. }),
        "{:?}",
        reply.body
    );
}

// ---------------------------------------------------------------------------
// The tests.
// ---------------------------------------------------------------------------

#[test]
fn a_push_from_the_app_reaches_the_browser_between_replies() {
    let app = App::bind();
    let (ready, go) = channel::<()>();
    let (done, finished) = channel::<()>();
    let mut browser = Browser::launch(&app);

    let server = std::thread::spawn(move || {
        let mut conn = app.accept();
        let hello = conn.read_request();
        conn.reply(&hello.id, &welcome());
        // Nothing is in flight: this is the app speaking first.
        assert!(conn.push(locate("p1")));
        ready.send(()).unwrap();
        // And mid-call: the push goes out before the reply to the request it arrives during.
        let status = conn.read_request();
        assert!(conn.push(Push::Deliver {
            probe_id: "p1".to_owned(),
            grant_id: "g1".to_owned(),
        }));
        conn.reply(&status.id, &Response::Status { unlocked: true });
        let _ = finished.recv();
    });

    browser.send("h", &hello());
    let (welcomed, mut early) = browser.reply_among_pushes("h");
    assert_welcome(&welcomed, "h");
    go.recv_timeout(PATIENCE).expect("the app pushed");
    // The browser sends nothing after its hello, and still the push arrives.
    if early.is_empty() {
        early.push(browser.next_push());
    }
    assert_eq!(early, [locate("p1")]);

    browser.send("s", &Request::Status);
    let (mut pushes, mut replies) = (Vec::new(), Vec::new());
    for _ in 0..2 {
        match browser.next() {
            Frame::Push(push) => pushes.push(push),
            Frame::Reply(reply) => replies.push(reply),
        }
    }
    assert_eq!(
        pushes,
        [Push::Deliver {
            probe_id: "p1".to_owned(),
            grant_id: "g1".to_owned(),
        }]
    );
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].id, "s");
    assert_eq!(replies[0].body, Response::Status { unlocked: true });

    let _ = done.send(());
    let (rest, stderr, _) = browser.close();
    server.join().expect("app thread");
    assert!(rest.is_empty(), "nothing else was sent: {rest:?}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn a_malformed_app_frame_is_dropped_not_forwarded() {
    let app = App::bind();
    let (done, finished) = channel::<()>();
    let mut browser = Browser::launch(&app);

    let server = std::thread::spawn(move || {
        let mut conn = app.accept();
        let hello = conn.read_request();
        conn.reply(&hello.id, &welcome());

        // Not JSON at all.
        conn.raw(format!("not json {APP_CANARY}").as_bytes());
        // A push of a kind the protocol does not have.
        conn.raw(
            format!(r#"{{"ksx":1,"push":{{"push":"exfiltrate","value":"{APP_CANARY}"}}}}"#)
                .as_bytes(),
        );
        // Both a reply and a push.
        conn.raw(
            format!(
                r#"{{"ksx":1,"id":"{APP_CANARY}","body":{{"reply":"noted"}},{}}}"#,
                r#""push":{"push":"locate","probe_id":"x"}"#
            )
            .as_bytes(),
        );
        // A reply to nothing anyone asked, that does not parse either.
        conn.raw(
            format!(r#"{{"ksx":1,"id":"nobody","body":{{"reply":"{APP_CANARY}"}}}}"#).as_bytes(),
        );
        // No channel marker.
        conn.raw(br#"{"push":{"push":"locate","probe_id":"unmarked"}}"#);
        // A well-formed push with a field the protocol does not have: it is forwarded, but as
        // the host re-encodes it, so the extra field is not.
        conn.raw(
            format!(
                r#"{{"ksx":1,"push":{{"push":"locate","probe_id":"p0","value":"{APP_CANARY}"}}}}"#
            )
            .as_bytes(),
        );
        assert!(conn.push(locate("p1")));

        // The reply to the browser's request, malformed — and quoting the canary where a value
        // would be.
        let first = conn.read_request();
        conn.raw(
            format!(
                r#"{{"ksx":1,"id":"{}","body":{{"reply":"status","unlocked":"{APP_CANARY}"}}}}"#,
                first.id
            )
            .as_bytes(),
        );
        // The stream is still in sync, so the connection is still good for the next request.
        let second = conn.read_request();
        conn.reply(&second.id, &Response::Status { unlocked: true });
        let _ = finished.recv();
    });

    browser.send("h", &hello());
    let (welcomed, mut pushes) = browser.reply_among_pushes("h");
    assert_welcome(&welcomed, "h");
    while pushes.len() < 2 {
        pushes.push(browser.next_push());
    }
    assert_eq!(
        pushes,
        [locate("p0"), locate("p1")],
        "the two pushes, and nothing else"
    );

    browser.send("a", &Request::Status);
    let refused = browser.next_reply();
    assert_eq!(
        refused.id, "a",
        "the request is answered, once, on its own id"
    );
    match &refused.body {
        Response::Error { code, .. } => assert_eq!(*code, ErrorCode::Protocol),
        other => panic!("an unreadable reply must be refused, not passed on: {other:?}"),
    }

    browser.send("b", &Request::Status);
    let answered = browser.next_reply();
    assert_eq!(answered.id, "b");
    assert_eq!(answered.body, Response::Status { unlocked: true });

    let _ = done.send(());
    let (rest, stderr, seen) = browser.close();
    server.join().expect("app thread");
    assert!(
        rest.is_empty(),
        "nothing else reached the browser: {rest:?}"
    );
    let seen = String::from_utf8_lossy(&seen);
    assert!(
        !seen.contains(APP_CANARY),
        "app bytes were copied to the browser: {seen}"
    );
    assert!(!stderr.contains(APP_CANARY), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn every_request_is_still_answered_exactly_once_in_order() {
    const REQUESTS: usize = 100;
    const PUSHES: usize = 500;

    let app = App::bind();
    let (done, finished) = channel::<()>();
    let mut browser = Browser::launch(&app);

    let server = std::thread::spawn(move || {
        let mut conn = app.accept();
        let hello = conn.read_request();
        conn.reply(&hello.id, &welcome());
        // Pushes from a thread of their own, racing every reply for the socket and the host's
        // stdout.
        let writer = Arc::clone(&conn.writer);
        let pusher = std::thread::spawn(move || {
            for n in 0..PUSHES {
                let mut writer = writer.lock().unwrap();
                frame::write(&mut *writer, &PushEnvelope::new(locate(&format!("q{n}"))))
                    .expect("push");
            }
        });
        for _ in 0..REQUESTS {
            let request = conn.read_request();
            let Request::Match { page } = request.body else {
                panic!("expected a match, got {:?}", request.body);
            };
            conn.reply(
                &request.id,
                &Response::Matches {
                    origin: page.top_origin,
                    items: vec![],
                },
            );
        }
        pusher.join().expect("pusher");
        let _ = finished.recv();
    });

    browser.send("h", &hello());
    let (welcomed, mut pushes) = browser.reply_among_pushes("h");
    assert_welcome(&welcomed, "h");

    // Everything at once, as a busy extension would.
    for n in 0..REQUESTS {
        browser.send(
            &format!("r{n}"),
            &Request::Match {
                page: PageContext::top(format!("https://s{n}.example")),
            },
        );
    }

    let mut replies = Vec::new();
    while pushes.len() < PUSHES || replies.len() < REQUESTS {
        match browser.next() {
            Frame::Push(push) => pushes.push(push),
            Frame::Reply(reply) => replies.push(reply),
        }
    }

    for (n, reply) in replies.iter().enumerate() {
        assert_eq!(
            reply.id,
            format!("r{n}"),
            "replies arrive in the order asked"
        );
        match &reply.body {
            Response::Matches { origin, .. } => {
                assert_eq!(
                    origin,
                    &format!("https://s{n}.example"),
                    "each its own answer"
                );
            }
            other => panic!("expected matches, got {other:?}"),
        }
    }
    let expected: Vec<Push> = (0..PUSHES).map(|n| locate(&format!("q{n}"))).collect();
    assert_eq!(
        pushes, expected,
        "every push, once, in the order the app sent them"
    );

    let _ = done.send(());
    let (rest, stderr, _) = browser.close();
    server.join().expect("app thread");
    assert!(rest.is_empty(), "no reply twice, nothing extra: {rest:?}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn the_host_exits_when_the_port_closes_while_pushes_are_flowing() {
    let app = App::bind();
    let (child, mut stdout) = spawn(&app);
    let mut browser = Browser::new(child);

    let server = std::thread::spawn(move || {
        let mut conn = app.accept();
        let hello = conn.read_request();
        conn.reply(&hello.id, &welcome());
        // As fast as the socket takes them, until the host is gone.
        let mut n = 0u64;
        while conn.push(locate(&format!("flood-{n}"))) {
            n += 1;
        }
    });

    browser.send("h", &hello());
    let (mut welcomed, mut pushes) = (false, 0);
    while !welcomed || pushes < 10 {
        let bytes = nm::read_bytes(&mut stdout).expect("a frame");
        match parse(&bytes) {
            Frame::Reply(reply) => {
                assert_welcome(&reply, "h");
                welcomed = true;
            }
            Frame::Push(_) => pushes += 1,
        }
    }

    // From here on nobody reads stdout: the pipe fills and the push forwarder blocks mid-write,
    // which is the worst moment for the port to close.
    drop(browser.stdin.take());
    let status = wait_for_exit(&mut browser.child);
    assert!(
        status.success(),
        "a closed port is a clean exit, got {status}"
    );
    drop(stdout);
    server
        .join()
        .expect("the app stops pushing once the host is gone");
}

#[test]
fn a_reconnect_says_hello_again() {
    let app = App::bind();
    let (closed, first_gone) = channel::<()>();
    let (seen, replays) = channel::<Vec<Envelope<Request>>>();
    let (done, finished) = channel::<()>();
    let mut browser = Browser::launch(&app);

    let server = std::thread::spawn(move || {
        // The first connection: a session, then the vault locks and the app hangs up.
        let mut first = app.accept();
        let hello = first.read_request();
        first.reply(&hello.id, &welcome());
        let status = first.read_request();
        first.reply(&status.id, &Response::Status { unlocked: true });
        drop(first);
        closed.send(()).unwrap();

        // The second: the replayed hello must come first, then the request that caused it.
        let mut second = app.accept();
        let replayed = second.read_request();
        second.reply(&replayed.id, &welcome());
        let next = second.read_request();
        second.reply(&next.id, &Response::Status { unlocked: true });
        drop(second);
        seen.send(vec![replayed, next]).unwrap();

        // The third: the browser says hello itself, and that is the only hello.
        let mut third = app.accept();
        let own = third.read_request();
        third.reply(&own.id, &welcome());
        let after = third.read_request();
        third.reply(&after.id, &Response::Status { unlocked: true });
        seen.send(vec![own, after]).unwrap();
        let _ = finished.recv();
    });

    browser.send("h1", &hello());
    assert_welcome(&browser.next_reply(), "h1");
    browser.send("s1", &Request::Status);
    assert_eq!(browser.next_reply().id, "s1");
    first_gone.recv_timeout(PATIENCE).expect("the app hung up");

    // Before this fix the new session had no hello behind it, and this was `PROTOCOL`.
    browser.send("s2", &Request::Status);
    let reply = browser.next_reply();
    assert_eq!(
        reply.id, "s2",
        "the replayed hello's answer is not the browser's"
    );
    assert_eq!(reply.body, Response::Status { unlocked: true });

    let second = replays
        .recv_timeout(PATIENCE)
        .expect("the second connection");
    assert_eq!(
        second[0],
        Envelope::new("h1", hello()),
        "the last hello, replayed as it was, capabilities and all"
    );
    assert_eq!(second[1], Envelope::new("s2", Request::Status));

    // A reconnect the browser's own hello causes is not preceded by a replay.
    browser.send("h2", &hello());
    assert_welcome(&browser.next_reply(), "h2");
    browser.send("s3", &Request::Status);
    assert_eq!(browser.next_reply().id, "s3");
    let third = replays
        .recv_timeout(PATIENCE)
        .expect("the third connection");
    assert_eq!(third[0], Envelope::new("h2", hello()));
    assert_eq!(third[1], Envelope::new("s3", Request::Status));

    let _ = done.send(());
    let (rest, stderr, _) = browser.close();
    server.join().expect("app thread");
    assert!(
        rest.is_empty(),
        "the answer to a replayed hello never reaches the browser: {rest:?}"
    );
    assert!(!stderr.contains("panicked"), "{stderr}");
}
