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
//! ever puts a well-formed [`Request`] on the app's socket.
//!
//! # Errors go to the browser, never to stdout as text
//!
//! stdout is the native messaging port: a stray `println!` is a corrupt frame and a dead port.
//! Everything diagnostic goes to stderr, which Chrome collects into its own log, and every
//! failure the extension needs to act on is sent as a framed
//! [`Response::Error`].

#![forbid(unsafe_code)]

use std::io::{Read, Write};

use kagisecure_extension_ipc::client::{Client, ClientError};
use kagisecure_extension_ipc::nm;
use kagisecure_extension_ipc::protocol::{Envelope, ErrorCode, Request, Response};

fn main() {
    // A native messaging host that writes anything to stdout other than a frame breaks the port.
    // Locking both handles once, up front, also keeps a partially-written frame from interleaving
    // with anything else.
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();

    let code = run(&mut input, &mut output);
    std::process::exit(code);
}

/// The forwarding loop. Returns the process exit code.
fn run<R: Read, W: Write>(input: &mut R, output: &mut W) -> i32 {
    // Connected lazily and kept for the life of the port: reconnecting per message would mean a
    // new peer-identity check, a new `Hello`, and a new approval-lease context on every keystroke.
    let mut app: Option<Client> = None;

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
                if !reply(
                    output,
                    "malformed",
                    &Response::error(ErrorCode::Protocol, format!("unreadable request: {e}")),
                ) {
                    return 1;
                }
                continue;
            }
        };

        let id = envelope.id.clone();
        let response = match forward(&mut app, &id, &envelope.body) {
            Ok(response) => response,
            Err(e) => {
                // A dead connection is worth one retry: the app may have restarted between two
                // keystrokes, and asking the user to reload the extension for that is silly.
                app = None;
                match forward(&mut app, &id, &envelope.body) {
                    Ok(response) => response,
                    Err(_) => Response::error(code_for(&e), e.to_string()),
                }
            }
        };

        if !reply(output, &id, &response) {
            return 1;
        }
    }
}

/// Send one request to the app, connecting first if necessary.
fn forward(app: &mut Option<Client>, id: &str, request: &Request) -> Result<Response, ClientError> {
    if app.is_none() {
        *app = Some(Client::connect_default()?);
    }
    let client = app.as_mut().expect("just connected");
    client.call(id, request)
}

/// Write one framed reply. `false` means the port is gone and the process should stop.
fn reply<W: Write>(output: &mut W, id: &str, response: &Response) -> bool {
    match nm::write(output, &Envelope::new(id, response)) {
        Ok(()) => true,
        Err(nm::NmError::TooLarge { size, limit }) => {
            // Chrome would drop the port silently. Say what happened, and try to say it in a
            // frame small enough to survive.
            eprintln!(
                "kagisecure-nmhost: reply of {size} bytes exceeds Chrome's {limit}-byte limit"
            );
            nm::write(
                output,
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

/// Map a transport failure onto the code the extension branches on.
fn code_for(error: &ClientError) -> ErrorCode {
    match error {
        ClientError::AppNotRunning => ErrorCode::VaultLocked,
        ClientError::Correlation { .. } => ErrorCode::Protocol,
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
        let mut output = Vec::new();
        assert_eq!(run(&mut input, &mut output), 0);
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
        let mut output = Vec::new();
        assert_eq!(run(&mut input, &mut output), 0);
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
        let mut output = Vec::new();
        assert_eq!(
            run(&mut input, &mut output),
            1,
            "a frame past the limit is a protocol violation, not something to answer"
        );
        assert!(output.is_empty());
    }

    #[test]
    fn with_no_app_listening_every_request_is_answered_with_vault_locked() {
        // `connect_default()` reads `KAGISECURE_EXTENSION_SOCKET`, and the harness does not set
        // it, so this exercises the real "the app is not running" path on a machine where it is
        // not — which is the state a browser is usually in.
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
        let mut output = Vec::new();
        assert_eq!(run(&mut input, &mut output), 0);
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
        let mut output = Vec::new();
        assert_eq!(run(&mut input, &mut output), 0);
        let len = u32::from_ne_bytes(output[..4].try_into().unwrap()) as usize;
        assert_eq!(len, output.len() - 4);
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
}
