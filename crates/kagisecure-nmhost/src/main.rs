//! `kagisecure-nmhost` — the Chrome native messaging host.
//!
//! # What this program is
//!
//! A pipe. Chrome launches it as a child process when the extension calls
//! `chrome.runtime.connectNative`, hands it stdin and stdout, and expects native-messaging frames
//! on both. This program reads a frame from stdin, writes it to the app's extension socket, reads
//! the reply, and writes it back to stdout. Then it does that again until the browser closes the
//! port.
//!
//! On macOS and Linux it also carries the other direction: the app may speak first (ADR-0036
//! §3.1), with a [`Push`] — a doorbell that carries two opaque ids and nothing else — and this
//! program writes each one to stdout as it arrives, between replies. See "Two directions" below.
//!
//! # What this program is deliberately not
//!
//! It is **not** a place decisions are made, and it holds **no** vault. It links exactly one
//! kagisecure crate, `kagisecure-extension-ipc`, which depends on `kagisecure-core` with the
//! `proto` feature and not `secret-material` — so this binary cannot name `Secret`, cannot open a
//! vault file, and has no code path that could unlock one. Everything that matters — matching an
//! origin, asking the human, minting a lease, reading a field — happens in the app, behind a
//! socket that checks who connected.
//!
//! That is the whole design: Chrome cannot verify the binary it launches (it launches whatever
//! the manifest names, with no signature check of any kind), so the correct amount of
//! authority to give the thing Chrome launches is none. See
//! [ADR-0019](../../../docs/decisions/0019-native-messaging-forwarder.md) and
//! `docs/threat-model-browser-extension.md` §3 "rogue native host".
//!
//! # Why the frames are re-encoded rather than copied
//!
//! A forwarder that copied bytes would forward anything, including a frame that is not an
//! envelope of this protocol at all. Decoding and re-encoding costs a JSON round trip per message
//! on a path that is about to show a human a dialog, and buys the property that this program only
//! ever puts a well-formed [`Request`] on the app's socket — and, in the other direction, only
//! ever puts a well-formed reply or a freshly built
//! [`PushEnvelope`](kagisecure_extension_ipc::protocol::PushEnvelope) on stdout. A frame from the
//! app that is neither is dropped, not passed on.
//!
//! # Two directions
//!
//! Requests are still answered one at a time, in the order the browser sent them, each exactly
//! once: the forwarding loop sends a request and waits for the reply with its id, as it always
//! has. Pushes arrive on the same socket at any moment, so the connection is a
//! [`DuplexClient`]: its reader thread routes each reply to the call waiting on it and hands each
//! push to a channel, and a second thread here ([`forward_pushes`]) writes those to stdout. Both
//! writers go through one [`Output`], a mutex around stdout held for a whole frame, so a push and
//! a reply never interleave their bytes. Each direction keeps its own order — replies in the
//! order the requests came, pushes in the order the app sent them — but a push is not ordered
//! against the replies: one the app sends just after a reply may reach the browser just before
//! it. Nothing depends on that order; a push is a doorbell, and what follows it is a new request.
//!
//! The connection is opened on the browser's first request — which is its `Hello` — and kept for
//! the life of the port, so a push has a way in whenever the extension has a session.
//!
//! **Windows is lock-step, and forwards no pushes.** A client pipe there cannot be read and
//! written at once (see `kagisecure_ipc::connect`), so the duplex client reads only during a call,
//! and a reader of this program's own would deadlock against the writes. Windows never offers
//! agent fills (ADR-0036 §12), so no push is sent there; one that arrived anyway would be dropped.
//!
//! # Saying hello again after a reconnect
//!
//! The app's listener stops when the vault locks and comes back when it unlocks, and its session
//! state — which extension said hello, and what it declared it can do — goes with the old
//! connection. This program reconnects on the next request, and before forwarding anything else
//! on the new connection it replays the last `Hello` it forwarded (a `Hello` carries no value), so
//! the new session starts where the old one was. The app's answer to the replay is this program's
//! own business: it is read and dropped, never written to stdout, because the browser did not ask
//! for it and has nothing waiting on its id.
//!
//! # Errors go to the browser, never to stdout as text
//!
//! stdout is the native messaging port: a stray `println!` is a corrupt frame and a dead port.
//! Everything diagnostic goes to stderr, which Chrome collects into its own log, and every
//! failure the extension needs to act on is sent as a framed
//! [`Response::Error`].
//!
//! # The browser closing the port ends this process, whatever it is doing
//!
//! Closing the host's stdin is how a browser says the port is finished. Whether, and how soon, it
//! also terminates the process is the browser's business, and on Windows nothing ties a child's
//! lifetime to its parent's — so this program must not depend on either. The forwarding loop
//! only reads stdin *between* round trips, so a host parked on the app — waiting for a reply,
//! or for a busy pipe to free up — would not see the port close until the app answered, and
//! would outlive the browser if it never did. So stdin is read on a thread of its
//! own ([`watch_stdin`]): the forwarding loop still consumes it in order, and still answers
//! whatever it had already been sent, but once the port has closed the process exits after
//! [`PORT_CLOSED_GRACE`] regardless of what the loop is waiting on — or what the push forwarder
//! is writing.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use kagisecure_extension_ipc::client::{Client, ClientError, DuplexClient};
use kagisecure_extension_ipc::frame::FrameError;
use kagisecure_extension_ipc::nm;
use kagisecure_extension_ipc::protocol::{Envelope, ErrorCode, Push, Request, Response};
// Windows forwards no pushes, so it never builds a push frame.
#[cfg(not(windows))]
use kagisecure_extension_ipc::protocol::PushEnvelope;

/// How long the host may keep running after the browser closes stdin.
///
/// Long enough to answer, in the ordinary case, whatever it had already been sent — a round trip
/// to a responsive app is milliseconds — and short enough that a host stuck on an app that never
/// answers is gone before anyone would notice it. A reply still owed when this runs out has no
/// one to go to: the browser closed the port.
const PORT_CLOSED_GRACE: Duration = Duration::from_secs(5);

/// How many stdin reads may be queued ahead of the forwarding loop before the reader stops
/// reading. Backpressure, so a browser that writes faster than the app answers is held at the
/// pipe rather than buffered here without limit.
const STDIN_QUEUE: usize = 16;

fn main() {
    // A native messaging host that writes anything to stdout other than a frame breaks the port.
    // Every frame goes through `Output`, which holds its lock for the whole frame, so the replies
    // and the pushes — written from two threads — never interleave. stdin belongs to the watcher
    // thread.
    let output = Output::new(std::io::stdout());
    let mut input = watch_stdin(PORT_CLOSED_GRACE);

    let code = run(&mut input, &output, Client::connect_default);
    std::process::exit(code);
}

/// Read stdin on its own thread, and exit the process `grace` after it closes.
///
/// Returns the reading end: a [`Read`] that yields exactly the bytes stdin did, in order, then
/// end-of-stream (or the error stdin failed with). The exit is `0`, the same code [`run`] returns
/// for a port the browser closed.
fn watch_stdin(grace: Duration) -> Pumped {
    let (tx, rx) = sync_channel(STDIN_QUEUE);
    std::thread::Builder::new()
        .name("kagisecure-nmhost-stdin".to_owned())
        .spawn(move || {
            pump(&mut std::io::stdin().lock(), &tx);
            drop(tx);
            std::thread::sleep(grace);
            std::process::exit(0);
        })
        .expect("could not start the stdin reader");
    Pumped::new(rx)
}

/// Copy `from` into `to` a read at a time until end-of-stream, an error, or nobody listening.
fn pump<R: Read>(from: &mut R, to: &SyncSender<std::io::Result<Vec<u8>>>) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let chunk = match from.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => Ok(buf[..n].to_vec()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => Err(e),
        };
        let failed = chunk.is_err();
        if to.send(chunk).is_err() || failed {
            return;
        }
    }
}

/// The forwarding loop's view of stdin, fed by [`pump`].
struct Pumped {
    rx: Receiver<std::io::Result<Vec<u8>>>,
    chunk: Vec<u8>,
    at: usize,
}

impl Pumped {
    fn new(rx: Receiver<std::io::Result<Vec<u8>>>) -> Self {
        Self {
            rx,
            chunk: Vec::new(),
            at: 0,
        }
    }
}

impl Read for Pumped {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.at == self.chunk.len() {
            // Block for the next chunk; a closed channel is the pump having finished, which is
            // stdin's end-of-stream.
            match self.rx.recv() {
                Ok(Ok(chunk)) => {
                    self.chunk = chunk;
                    self.at = 0;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(0),
            }
        }
        let n = buf.len().min(self.chunk.len() - self.at);
        buf[..n].copy_from_slice(&self.chunk[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// stdout, shared by the forwarding loop and the push forwarder: one whole frame per lock.
struct Output<W>(Arc<Mutex<W>>);

impl<W> Clone for Output<W> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<W: Write> Output<W> {
    fn new(writer: W) -> Self {
        Self(Arc::new(Mutex::new(writer)))
    }

    /// Lock the port for one frame. `None` if a writer panicked holding it: part of a frame may
    /// be on the pipe, and nothing written after it would be read as what it is.
    fn lock(&self) -> Option<MutexGuard<'_, W>> {
        if let Ok(guard) = self.0.lock() {
            Some(guard)
        } else {
            eprintln!("kagisecure-nmhost: a writer failed mid-frame; the port is unusable");
            None
        }
    }

    /// Write one framed reply. `false` means the port is gone and the process should stop.
    fn reply(&self, id: &str, response: &Response) -> bool {
        let Some(mut output) = self.lock() else {
            return false;
        };
        match nm::write(&mut *output, &Envelope::new(id, response)) {
            Ok(()) => true,
            Err(nm::NmError::TooLarge { size, limit }) => {
                // Chrome would drop the port silently. Say what happened, and try to say it in a
                // frame small enough to survive. Nothing of the first frame was written: its size
                // is checked before its first byte.
                eprintln!(
                    "kagisecure-nmhost: reply of {size} bytes exceeds Chrome's {limit}-byte limit"
                );
                nm::write(
                    &mut *output,
                    &Envelope::new(
                        id,
                        Response::error(ErrorCode::Internal, "the reply was too large to send"),
                    ),
                )
                .is_ok()
            }
            Err(e) => {
                eprintln!("kagisecure-nmhost: {e}");
                false
            }
        }
    }

    /// Write one push, in a [`PushEnvelope`] built here. `false` means the port is gone.
    ///
    /// Not on Windows, which forwards no pushes (see "Two directions" above).
    #[cfg(not(windows))]
    fn push(&self, push: Push) -> bool {
        let Some(mut output) = self.lock() else {
            return false;
        };
        match nm::write(&mut *output, &PushEnvelope::new(push)) {
            Ok(()) => true,
            // Only an app sending ids no real probe has could get here. There is no request to
            // answer in its place, so the push is dropped and the port lives on.
            Err(nm::NmError::TooLarge { size, limit }) => {
                eprintln!(
                    "kagisecure-nmhost: dropped a push of {size} bytes, past Chrome's \
                     {limit}-byte limit"
                );
                true
            }
            Err(e) => {
                eprintln!("kagisecure-nmhost: {e}");
                false
            }
        }
    }
}

/// The forwarding loop. Returns the process exit code.
///
/// `connector` opens the connection to the app. It is a parameter so that what a request meets
/// can be chosen by the caller instead of by whatever is listening on the machine the program
/// runs on: `main` passes [`Client::connect_default`], the tests pass a stand-in.
fn run<R: Read, W: Write + Send + 'static>(
    input: &mut R,
    output: &Output<W>,
    connector: Connector,
) -> i32 {
    let mut session = Session::new(output.clone(), connector);

    loop {
        let raw = match nm::read_bytes(input) {
            Ok(bytes) => bytes,
            Err(nm::NmError::Closed) => return 0,
            Err(e) => {
                eprintln!("kagisecure-nmhost: {e}");
                return 1;
            }
        };

        // Decode before forwarding, so only well-formed requests reach the app's socket.
        let envelope: Envelope<Request> = match serde_json::from_slice(&raw) {
            Ok(envelope) => envelope,
            Err(e) => {
                // No id to correlate against — the frame did not parse — so answer on a fixed one
                // the extension treats as "the last thing you sent was rejected".
                if !output.reply(
                    "malformed",
                    &Response::error(ErrorCode::Protocol, format!("unreadable request: {e}")),
                ) {
                    return 1;
                }
                continue;
            }
        };

        let response = session.forward(&envelope);
        if !output.reply(&envelope.id, &response) {
            return 1;
        }
    }
}

/// How a [`Session`] opens its connection to the app.
type Connector = fn() -> Result<Client, ClientError>;

/// The forwarding loop's state from one request to the next.
struct Session<W> {
    connector: Connector,
    /// Where pushes go: the same port the replies do.
    output: Output<W>,
    /// The connection to the app. Opened on the first request and kept for the life of the port:
    /// reconnecting per message would mean a new peer-identity check, a new `Hello`, and a new
    /// approval-lease context on every keystroke — and nowhere for a push to arrive between them.
    app: Option<DuplexClient>,
    /// The last `Hello` the browser sent and this program forwarded, replayed on a new connection
    /// before anything else is (see the module documentation). It carries the extension's id, its
    /// version, the protocol version and its capabilities: no value.
    hello: Option<Envelope<Request>>,
}

impl<W: Write + Send + 'static> Session<W> {
    fn new(output: Output<W>, connector: Connector) -> Self {
        Self {
            connector,
            output,
            app: None,
            hello: None,
        }
    }

    /// Send one request to the app and return the reply the browser should get for it.
    fn forward(&mut self, envelope: &Envelope<Request>) -> Response {
        if matches!(envelope.body, Request::Hello { .. }) {
            self.hello = Some(envelope.clone());
        }
        match self.attempt(envelope) {
            Ok(response) => return response,
            // The app answered, or could have: sending the request again could ask twice.
            Err(e) if !connection_lost(&e) => return failure(&e),
            Err(_) => {}
        }
        // A dead connection is worth one retry: the app may have restarted, or locked and
        // unlocked, between two keystrokes, and asking the user to reload the extension for that
        // is silly.
        match self.attempt(envelope) {
            Ok(response) => response,
            // The retry's failure is the one reported, not the first: the first is about a
            // connection that is gone, the retry's about what holds the endpoint now — nothing
            // (the app is not running), or a pipe of another account's — which is what the user
            // can act on. Reporting the first used to turn "another account holds the endpoint"
            // into a bare "connection closed".
            Err(retry) => failure(&retry),
        }
    }

    /// One try: connect if there is no connection, then call.
    fn attempt(&mut self, envelope: &Envelope<Request>) -> Result<Response, ClientError> {
        let client = match self.app.take() {
            Some(client) => client,
            None => self.connect(&envelope.body)?,
        };
        let result = client.call(&envelope.id, &envelope.body);
        match &result {
            // Gone, or out of step with this program: either way nothing more will be answered on
            // it, and the next request starts a new one.
            Err(e) if connection_lost(e) || matches!(e, ClientError::Correlation { .. }) => {}
            _ => self.app = Some(client),
        }
        result
    }

    /// Open a connection, start forwarding its pushes, and — unless `request` is itself a
    /// `Hello` — replay the last `Hello` on it.
    fn connect(&self, request: &Request) -> Result<DuplexClient, ClientError> {
        let (client, pushes) = (self.connector)()?.into_duplex()?;
        forward_pushes(pushes, &self.output);
        if let Some(hello) = &self.hello
            && !matches!(request, Request::Hello { .. })
        {
            // The answer is this program's, not the browser's: it did not ask, and nothing on its
            // side waits on this id any more. A refusal is left for the request that follows to
            // run into, exactly as it would have without the replay.
            match client.call(&hello.id, &hello.body)? {
                Response::Welcome { .. } => {
                    eprintln!(
                        "kagisecure-nmhost: reconnected, and said the extension's hello again"
                    );
                }
                Response::Error { code, .. } => {
                    eprintln!(
                        "kagisecure-nmhost: reconnected; the app refused the hello ({code:?})"
                    );
                }
                _ => eprintln!("kagisecure-nmhost: reconnected; the app answered hello oddly"),
            }
        }
        Ok(client)
    }
}

/// Write every push the app sends on this connection to stdout, as it arrives.
///
/// The thread ends when the connection does: the channel closes when the client's reader thread
/// sees the app hang up. A push is re-encoded in a [`PushEnvelope`] built here from the typed
/// [`Push`], never copied: an app frame that did not parse as a push or a reply was already
/// dropped by the reader.
#[cfg(not(windows))]
fn forward_pushes<W: Write + Send + 'static>(pushes: Receiver<Push>, output: &Output<W>) {
    let output = output.clone();
    let started = std::thread::Builder::new()
        .name("kagisecure-nmhost-pushes".to_owned())
        .spawn(move || {
            for push in pushes {
                if !output.push(push) {
                    return;
                }
            }
        });
    if let Err(e) = started {
        // Replies still flow; only the doorbell is missing, and the app treats an unanswered
        // probe as no tab at all.
        eprintln!("kagisecure-nmhost: could not start forwarding pushes: {e}");
    }
}

/// Windows: pushes are not forwarded. See "Two directions" in the module documentation.
#[cfg(windows)]
fn forward_pushes<W: Write + Send + 'static>(pushes: Receiver<Push>, output: &Output<W>) {
    let _ = output;
    drop(pushes);
}

/// Whether `error` means the connection is gone, or never came up, before the app answered — so
/// there is nothing to keep, and one retry on a new connection is the right move. Everything else
/// is an answer, or a request that could not be sent at all, and is reported as it is.
fn connection_lost(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::Frame(FrameError::Closed | FrameError::Io(_))
            | ClientError::AppNotRunning
            | ClientError::ForeignServer
            | ClientError::Endpoint(_)
    )
}

/// The reply the browser gets when a request could not be answered by the app.
fn failure(error: &ClientError) -> Response {
    let message = match error {
        // The parser's message can quote the bytes it failed on, and the reply it failed on may
        // have been a `filled`. It is not repeated to anyone.
        ClientError::Frame(FrameError::InvalidBody { .. }) => {
            "The app's reply could not be read.".to_owned()
        }
        other => other.to_string(),
    };
    Response::error(code_for(error), message)
}

/// Map a transport failure onto the code the extension branches on.
///
/// # `ForeignServer` is `INTERNAL`, deliberately, and not a new code
///
/// A pipe held by another account is a different situation from every code the protocol has,
/// and the ones that sound close would each tell the user something false:
///
/// * `VAULT_LOCKED` — the popup shows "The vault is locked" and the page offers "Unlock it and try
///   again". Unlocking does nothing while someone else holds the name, so that sends the user in
///   a circle. (`AppNotRunning` maps here on purpose: there, opening the app *is* the fix.)
/// * `UNTRUSTED_HOST` — the page says "Kagisecure does not recognize this browser connection.
///   Re-run setup in the app." That is the app refusing the host; this is the host refusing what
///   answered in the app's place, and re-running setup does not move a squatter.
///
/// A distinct code (`FOREIGN_ENDPOINT`, say) would be the precise answer, but it is a protocol
/// change: the extension's `friendly()` in `extensions/shared/content.js` and the popup would have
/// to learn it, and an older extension would show it as an unknown code anyway. `INTERNAL`
/// already renders the way this needs: `friendly()`'s default arm and the popup's error state
/// both show the reply's **message**, and [`ClientError::ForeignServer`]'s message says what
/// happened — the endpoint is held by another account, and nothing was sent to it. The MCP
/// channel made the same choice (`kagisecure_ipc::ClientError::code`).
fn code_for(error: &ClientError) -> ErrorCode {
    match error {
        ClientError::AppNotRunning => ErrorCode::VaultLocked,
        // The app's side of the wire made no sense: a reply to a request nobody made, or one
        // that did not parse.
        ClientError::Correlation { .. } | ClientError::Frame(FrameError::InvalidBody { .. }) => {
            ErrorCode::Protocol
        }
        ClientError::ForeignServer => ErrorCode::Internal,
        _ => ErrorCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagisecure_extension_ipc::protocol::PageContext;

    /// Frame `request` the way Chrome would.
    fn browser_frame(id: &str, request: &Request) -> Vec<u8> {
        let mut buf = Vec::new();
        nm::write(&mut buf, &Envelope::new(id, request)).expect("frame");
        buf
    }

    /// The app is not running. Chosen explicitly rather than by resolving the real endpoint: on a
    /// machine where Kagisecure is running, that socket is answered by the real app, which
    /// refuses this test binary's parent (`cargo test`, not a browser) with `UntrustedHost` — so
    /// the outcome would depend on what else is running and who launched the test.
    fn no_app_listening() -> Result<Client, ClientError> {
        Err(ClientError::AppNotRunning)
    }

    /// Run the forwarding loop over `input` and return its exit code and everything it framed.
    fn run_collecting<R: Read>(input: &mut R) -> (i32, Vec<u8>) {
        let output = Output::new(Vec::new());
        let code = run(input, &output, no_app_listening);
        let bytes = output.lock().expect("no writer panicked").clone();
        (code, bytes)
    }

    fn responses(bytes: &[u8]) -> Vec<Envelope<Response>> {
        let mut cursor = bytes;
        let mut out = Vec::new();
        while let Ok(envelope) = nm::read::<_, Envelope<Response>>(&mut cursor) {
            out.push(envelope);
        }
        out
    }

    #[test]
    fn a_closed_port_exits_cleanly() {
        let mut input: &[u8] = &[];
        let (code, output) = run_collecting(&mut input);
        assert_eq!(code, 0);
        assert!(output.is_empty());
    }

    #[test]
    fn a_malformed_frame_is_answered_rather_than_forwarded() {
        let mut input: &[u8] = &{
            let body = br#"{"not":"an envelope"}"#;
            let mut buf = Vec::new();
            buf.extend_from_slice(&u32::try_from(body.len()).unwrap().to_ne_bytes());
            buf.extend_from_slice(body);
            buf
        };
        let (code, output) = run_collecting(&mut input);
        assert_eq!(code, 0);
        let replies = responses(&output);
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].id, "malformed");
        assert!(matches!(
            replies[0].body,
            Response::Error {
                code: ErrorCode::Protocol,
                ..
            }
        ));
    }

    #[test]
    fn an_oversized_declared_length_stops_the_host_instead_of_allocating() {
        let mut input: &[u8] = &u32::MAX.to_ne_bytes();
        let (code, output) = run_collecting(&mut input);
        assert_eq!(
            code, 1,
            "a frame past the limit is a protocol violation, not something to answer"
        );
        assert!(output.is_empty());
    }

    #[test]
    fn with_no_app_listening_every_request_is_answered_with_vault_locked() {
        // The app being absent is injected, not discovered: see `no_app_listening`. The real
        // connect path against a missing socket is covered by `tests/framing_adversarial.rs`.
        let mut input: &[u8] = &{
            let mut buf = browser_frame("a", &Request::Status);
            buf.extend_from_slice(&browser_frame(
                "b",
                &Request::Match {
                    page: PageContext::top("https://example.com"),
                },
            ));
            buf
        };
        let (code, output) = run_collecting(&mut input);
        assert_eq!(code, 0);
        let replies = responses(&output);
        assert_eq!(replies.len(), 2, "every request gets exactly one reply");
        assert_eq!(replies[0].id, "a");
        assert_eq!(replies[1].id, "b");
        for reply in &replies {
            match &reply.body {
                Response::Error { code, .. } => assert_eq!(*code, ErrorCode::VaultLocked),
                other => panic!("expected an error, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_reply_frame_is_native_endian_like_chrome_expects() {
        let mut input: &[u8] = &browser_frame("a", &Request::Status);
        let (code, output) = run_collecting(&mut input);
        assert_eq!(code, 0);
        let len = u32::from_ne_bytes(output[..4].try_into().unwrap()) as usize;
        assert_eq!(len, output.len() - 4);
    }

    /// Run `bytes` through the same pump `main` puts in front of stdin, a few bytes per read so
    /// that frames straddle chunks.
    fn pumped(bytes: &[u8], read_size: usize) -> Pumped {
        struct Trickle<'a>(&'a [u8], usize);
        impl Read for Trickle<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.len().min(self.1).min(buf.len());
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let (tx, rx) = sync_channel(STDIN_QUEUE);
        let owned = bytes.to_vec();
        std::thread::spawn(move || pump(&mut Trickle(&owned, read_size), &tx));
        Pumped::new(rx)
    }

    #[test]
    fn the_pumped_port_is_the_same_bytes_in_the_same_order_then_closed() {
        let mut input = browser_frame("a", &Request::Status);
        input.extend_from_slice(&browser_frame("b", &Request::Status));
        for read_size in [1, 3, 7, 4096] {
            let mut through = Vec::new();
            pumped(&input, read_size)
                .read_to_end(&mut through)
                .expect("read");
            assert_eq!(through, input, "read size {read_size}");
        }
    }

    #[test]
    fn the_forwarding_loop_behaves_the_same_behind_the_pump() {
        // `main` hands `run` a `Pumped`, not stdin, so the unit tests above are only about the
        // binary if the two are indistinguishable to `run`.
        let mut input = browser_frame("a", &Request::Status);
        input.extend_from_slice(&browser_frame("b", &Request::Status));
        let (code, output) = run_collecting(&mut pumped(&input, 5));
        assert_eq!(code, 0);
        let replies = responses(&output);
        assert_eq!(
            replies.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    #[test]
    fn a_failing_port_is_an_error_after_the_bytes_before_it() {
        struct Breaks(bool);
        impl Read for Breaks {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if std::mem::replace(&mut self.0, true) {
                    Err(std::io::Error::other("the port broke"))
                } else {
                    buf[..2].copy_from_slice(b"ok");
                    Ok(2)
                }
            }
        }
        let (tx, rx) = sync_channel(STDIN_QUEUE);
        std::thread::spawn(move || pump(&mut Breaks(false), &tx));
        let mut reader = Pumped::new(rx);
        let mut buf = [0u8; 8];
        assert_eq!(reader.read(&mut buf).expect("first read"), 2);
        assert_eq!(&buf[..2], b"ok");
        let err = reader.read(&mut buf).unwrap_err();
        assert_eq!(err.to_string(), "the port broke");
    }

    #[test]
    fn a_transport_failure_maps_onto_a_code_the_extension_can_branch_on() {
        assert_eq!(
            code_for(&ClientError::AppNotRunning),
            ErrorCode::VaultLocked
        );
        assert_eq!(
            code_for(&ClientError::Correlation {
                got: "a".to_owned(),
                want: "b".to_owned()
            }),
            ErrorCode::Protocol
        );
    }

    /// A reply from the app that did not parse is answered with a fixed sentence. The parser's
    /// own message can quote the bytes it choked on, and those bytes may have been a `filled`.
    #[test]
    fn an_unreadable_app_reply_is_never_quoted_back() {
        const CANARY: &str = "NMH0ST-R3PLY-C4N4RY-91c0";
        let error = ClientError::Frame(FrameError::InvalidBody {
            id: Some("a".to_owned()),
            message: format!("invalid type: string \"{CANARY}\", expected a reply"),
        });
        let response = failure(&error);
        let text = serde_json::to_string(&response).expect("json");
        assert!(!text.contains(CANARY), "{text}");
        assert!(matches!(
            response,
            Response::Error {
                code: ErrorCode::Protocol,
                ..
            }
        ));
    }

    /// Only a connection that went away before answering is retried: a request the app did answer
    /// — oddly, or out of step — is not sent a second time, since a second `fill` would be a
    /// second sheet.
    #[test]
    fn only_a_lost_connection_is_worth_a_retry() {
        for lost in [
            ClientError::AppNotRunning,
            ClientError::ForeignServer,
            ClientError::Frame(FrameError::Closed),
            ClientError::Frame(FrameError::Io(std::io::Error::other("reset"))),
        ] {
            assert!(connection_lost(&lost), "{lost:?}");
        }
        for answered in [
            ClientError::Correlation {
                got: "a".to_owned(),
                want: "b".to_owned(),
            },
            ClientError::Frame(FrameError::InvalidBody {
                id: Some("a".to_owned()),
                message: String::new(),
            }),
            ClientError::Frame(FrameError::TooLarge(usize::MAX)),
            ClientError::IdInUse("a".to_owned()),
        ] {
            assert!(!connection_lost(&answered), "{answered:?}");
        }
    }

    /// A pipe held by another account must not read as "locked" (unlocking cannot fix it) or as
    /// "untrusted host" (re-running setup cannot either). `INTERNAL` is shown to the user by its
    /// message, so the message has to carry the explanation. See `code_for`.
    #[test]
    fn a_foreign_endpoint_is_reported_by_its_message_not_as_a_locked_vault() {
        let error = ClientError::ForeignServer;
        assert_eq!(code_for(&error), ErrorCode::Internal);
        let message = error.to_string();
        assert!(message.contains("another account"), "{message}");
        assert!(message.contains("nothing was sent"), "{message}");
    }
}
