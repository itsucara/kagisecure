//! Chrome native-messaging framing: a 4-byte **native-endian** length, then that many bytes of
//! UTF-8 JSON.
//!
//! # Native-endian, and why that is not a bug
//!
//! Every other length prefix in this project is explicitly ordered — little-endian in
//! `kagisecure_ipc::frame`, big-endian in [`crate::frame`]. This one is native-endian because
//! Chrome's is: the browser writes a `uint32` in the host machine's byte order, and a host that
//! insisted on a fixed order would be wrong on half the world's machines and right on the other
//! half by accident. The two processes are always on the same machine — a native messaging host
//! is launched by the browser as a child process — so "native" is unambiguous here in a way it
//! would not be on a network protocol.
//!
//! # The limits are Chrome's, not ours
//!
//! Chrome refuses a message **from** a native host larger than 1 MiB and disconnects the port.
//! [`MAX_HOST_TO_BROWSER`] is that limit, enforced on the way out so the failure is a legible
//! error in our own logs rather than a silent port closure the extension has to guess about.
//!
//! In the other direction Chrome permits far more than we ever want to read, so
//! [`MAX_BROWSER_TO_HOST`] caps it at the same 1 MiB: the largest thing an extension sends us is
//! a page origin and an item id. A declared length beyond the cap is refused **before** the
//! buffer is allocated, which is the whole point of checking it.

use std::io::{Read, Write};

/// Chrome's own limit on a message from a native host. Exceeding it closes the port.
pub const MAX_HOST_TO_BROWSER: usize = 1024 * 1024;

/// What this host will accept from the browser. Chrome allows more; we do not need it.
pub const MAX_BROWSER_TO_HOST: usize = 1024 * 1024;

/// Length prefix width.
const PREFIX: usize = 4;

/// What can go wrong on the stdio pipe.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NmError {
    /// The browser closed the port. The normal way a native host exits.
    #[error("the browser closed the native messaging port")]
    Closed,
    /// A declared or encoded length exceeded the limit for its direction.
    #[error("native message of {size} bytes exceeds the {limit}-byte limit")]
    TooLarge {
        /// How big the message was, or claimed to be.
        size: usize,
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The body was not JSON of the expected shape.
    #[error("malformed native message: {0}")]
    Malformed(String),
    /// Transport failure.
    #[error("i/o error on the native messaging port: {0}")]
    Io(#[from] std::io::Error),
}

/// Write one message to the browser.
///
/// # Errors
///
/// [`NmError::TooLarge`] if the encoded message exceeds [`MAX_HOST_TO_BROWSER`] — checked before
/// anything is written, so a rejected message does not leave half a frame on the pipe — or any
/// I/O failure.
pub fn write<W: Write, T: serde::Serialize>(w: &mut W, message: &T) -> Result<(), NmError> {
    let body = serde_json::to_vec(message).map_err(|e| NmError::Malformed(e.to_string()))?;
    write_bytes(w, &body)
}

/// Write pre-encoded JSON bytes to the browser.
///
/// The forwarder uses this: it has a frame it has already validated and does not need to decode
/// and re-encode it to pass it on.
///
/// # Errors
///
/// As [`write()`].
pub fn write_bytes<W: Write>(w: &mut W, body: &[u8]) -> Result<(), NmError> {
    if body.len() > MAX_HOST_TO_BROWSER {
        return Err(NmError::TooLarge {
            size: body.len(),
            limit: MAX_HOST_TO_BROWSER,
        });
    }
    let len = u32::try_from(body.len()).map_err(|_| NmError::TooLarge {
        size: body.len(),
        limit: MAX_HOST_TO_BROWSER,
    })?;
    // `to_ne_bytes`, deliberately: see the module docs.
    w.write_all(&len.to_ne_bytes())?;
    w.write_all(body)?;
    w.flush()?;
    Ok(())
}

/// Read one message from the browser as raw JSON bytes.
///
/// # Errors
///
/// [`NmError::Closed`] at a clean end of stream, [`NmError::TooLarge`] for a declared length past
/// [`MAX_BROWSER_TO_HOST`] (refused before allocating), or any I/O failure.
pub fn read_bytes<R: Read>(r: &mut R) -> Result<Vec<u8>, NmError> {
    let mut prefix = [0u8; PREFIX];
    match r.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(NmError::Closed),
        Err(e) => return Err(NmError::Io(e)),
    }
    let len = u32::from_ne_bytes(prefix) as usize;
    if len > MAX_BROWSER_TO_HOST {
        return Err(NmError::TooLarge {
            size: len,
            limit: MAX_BROWSER_TO_HOST,
        });
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            NmError::Closed
        } else {
            NmError::Io(e)
        }
    })?;
    Ok(body)
}

/// Read one message and deserialize it.
///
/// # Errors
///
/// As [`read_bytes`], plus [`NmError::Malformed`] when the body does not parse.
pub fn read<R: Read, T: serde::de::DeserializeOwned>(r: &mut R) -> Result<T, NmError> {
    let body = read_bytes(r)?;
    serde_json::from_slice(&body).map_err(|e| NmError::Malformed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Envelope, Request};

    #[test]
    fn a_message_survives_a_round_trip() {
        let mut buf = Vec::new();
        let envelope = Envelope::new("r1", Request::Status);
        write(&mut buf, &envelope).unwrap();
        let back: Envelope<Request> = read(&mut buf.as_slice()).unwrap();
        assert_eq!(back, envelope);
    }

    #[test]
    fn the_prefix_is_native_endian_and_the_body_is_json() {
        let mut buf = Vec::new();
        write(&mut buf, &Envelope::new("r1", Request::Status)).unwrap();
        let len = u32::from_ne_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(len, buf.len() - 4);
        let text = std::str::from_utf8(&buf[4..]).unwrap();
        assert!(
            text.starts_with('{') && text.contains("\"ask\":\"status\""),
            "{text}"
        );
    }

    #[test]
    fn several_messages_stream_back_in_order() {
        let mut buf = Vec::new();
        write(&mut buf, &Envelope::new("a", Request::Status)).unwrap();
        write(&mut buf, &Envelope::new("b", Request::Status)).unwrap();
        let mut cursor = buf.as_slice();
        assert_eq!(read::<_, Envelope<Request>>(&mut cursor).unwrap().id, "a");
        assert_eq!(read::<_, Envelope<Request>>(&mut cursor).unwrap().id, "b");
        assert!(matches!(
            read::<_, Envelope<Request>>(&mut cursor),
            Err(NmError::Closed)
        ));
    }

    #[test]
    fn an_oversized_declared_length_is_refused_before_allocating() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::MAX.to_ne_bytes());
        // Note there is no body at all: if the implementation allocated first it would either
        // hang or die here rather than returning.
        let err = read_bytes(&mut framed.as_slice()).unwrap_err();
        match err {
            NmError::TooLarge { size, limit } => {
                assert_eq!(size, u32::MAX as usize);
                assert_eq!(limit, MAX_BROWSER_TO_HOST);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn a_length_exactly_at_the_limit_is_accepted_and_one_past_it_is_not() {
        let mut at = Vec::new();
        at.extend_from_slice(&u32::try_from(MAX_BROWSER_TO_HOST).unwrap().to_ne_bytes());
        at.extend_from_slice(&vec![b'x'; MAX_BROWSER_TO_HOST]);
        assert_eq!(
            read_bytes(&mut at.as_slice()).unwrap().len(),
            MAX_BROWSER_TO_HOST
        );

        let mut past = Vec::new();
        past.extend_from_slice(
            &u32::try_from(MAX_BROWSER_TO_HOST + 1)
                .unwrap()
                .to_ne_bytes(),
        );
        assert!(matches!(
            read_bytes(&mut past.as_slice()),
            Err(NmError::TooLarge { .. })
        ));
    }

    #[test]
    fn an_oversized_outgoing_message_is_refused_without_writing_a_partial_frame() {
        let mut sink = Vec::new();
        let huge = vec![b'x'; MAX_HOST_TO_BROWSER + 1];
        assert!(matches!(
            write_bytes(&mut sink, &huge),
            Err(NmError::TooLarge { .. })
        ));
        assert!(
            sink.is_empty(),
            "a refused message must not leave a length prefix on the pipe"
        );
    }

    #[test]
    fn a_truncated_body_reads_as_a_close_rather_than_as_garbage() {
        let mut buf = Vec::new();
        write(&mut buf, &Envelope::new("a", Request::Status)).unwrap();
        buf.truncate(buf.len() - 2);
        assert!(matches!(
            read_bytes(&mut buf.as_slice()),
            Err(NmError::Closed)
        ));
    }

    #[test]
    fn an_empty_stream_reads_as_closed() {
        assert!(matches!(
            read_bytes(&mut [].as_slice()),
            Err(NmError::Closed)
        ));
    }

    #[test]
    fn garbage_inside_a_well_formed_frame_is_a_parse_error() {
        let body = br#"{"ksx":1,"id":"a","body":{"ask":"nope"}}"#;
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::try_from(body.len()).unwrap().to_ne_bytes());
        buf.extend_from_slice(body);
        assert!(matches!(
            read::<_, Envelope<Request>>(&mut buf.as_slice()),
            Err(NmError::Malformed(_))
        ));
    }

    #[test]
    fn a_zero_length_frame_is_read_as_an_empty_body_not_as_a_close() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_ne_bytes());
        assert_eq!(read_bytes(&mut buf.as_slice()).unwrap(), Vec::<u8>::new());
    }
}
