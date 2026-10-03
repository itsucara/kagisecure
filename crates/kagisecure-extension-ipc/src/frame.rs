//! The app-socket framing: a 4-byte **big-endian** length, then that many bytes of UTF-8 JSON.
//!
//! # Why big-endian when `kagisecure_ipc::frame` is little-endian
//!
//! Because the two sockets live in the same `0700` directory and a mistake — a misconfigured
//! path, a stale `KAGISECURE_SOCKET`, a copy-pasted setup snippet — should produce a loud failure
//! rather than a quiet misinterpretation. A `{"op":"ListVaults"}` frame arriving here declares a
//! preposterous length under the opposite byte order and is refused by the size check before a
//! byte of it is read; an extension frame arriving on the MCP socket fails the same way. The
//! belt to that brace is the `ksx` marker in [`crate::protocol::Envelope`], which stops any frame
//! that does survive the length check from parsing as a message.
//!
//! [`MAX_FRAME`] is 256 KiB rather than the MCP channel's 1 MiB: the largest thing this protocol
//! ever carries is a page origin, an item id and one password.

use std::io::{Read, Write};

/// Largest frame either side will send or accept on the app socket.
pub const MAX_FRAME: usize = 256 * 1024;

/// Length prefix width.
const PREFIX: usize = 4;

/// What can go wrong on the app socket.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// The peer closed the connection.
    #[error("the connection was closed")]
    Closed,
    /// The declared length exceeds [`MAX_FRAME`].
    #[error("frame of {0} bytes exceeds the {MAX_FRAME}-byte limit")]
    TooLarge(usize),
    /// A message could not be serialized to JSON. Only [`write()`] returns this; a `T` this crate
    /// defines does not fail to serialize in practice.
    #[error("malformed message: {0}")]
    Malformed(String),
    /// The frame was read in full — the length prefix and that many bytes — but the bytes did not
    /// deserialize into the requested type.
    ///
    /// Unlike [`FrameError::Closed`], [`FrameError::TooLarge`] or [`FrameError::Io`], the stream
    /// is still in sync: the next frame starts exactly where the declared length said it would.
    /// So this is the one variant a caller can answer instead of closing the connection over, and
    /// `id` carries the correlation id when the bytes at least parsed as an object with one —
    /// recovered independently of the target type `T`, since `T` is exactly what failed to parse.
    #[error("frame body did not deserialize: {message}")]
    InvalidBody {
        /// The envelope's correlation id, if the malformed body at least had one.
        id: Option<String>,
        /// The `serde_json` error, for logs.
        message: String,
    },
    /// Transport failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Serialize `message` and write it as one frame.
///
/// # Errors
///
/// [`FrameError::TooLarge`] if the encoded message exceeds [`MAX_FRAME`], or any I/O failure.
pub fn write<W: Write, T: serde::Serialize>(w: &mut W, message: &T) -> Result<(), FrameError> {
    let body = serde_json::to_vec(message).map_err(|e| FrameError::Malformed(e.to_string()))?;
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge(body.len()))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Read one frame and deserialize it.
///
/// # Errors
///
/// [`FrameError::Closed`] on a clean end of stream, [`FrameError::TooLarge`] for an oversized
/// declared length (refused before allocating), [`FrameError::InvalidBody`] for a frame that was
/// read in full but whose bytes do not deserialize as `T`, or any I/O failure.
pub fn read<R: Read, T: serde::de::DeserializeOwned>(r: &mut R) -> Result<T, FrameError> {
    let mut prefix = [0u8; PREFIX];
    match r.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(e) => return Err(FrameError::Io(e)),
    }
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            FrameError::Closed
        } else {
            FrameError::Io(e)
        }
    })?;
    serde_json::from_slice(&body).map_err(|e| FrameError::InvalidBody {
        id: id_of(&body),
        message: e.to_string(),
    })
}

/// Recover the envelope's correlation id from a body that failed to deserialize as `T`.
///
/// Parsed independently of `T` — as a bare `{"id": ...}` — since `T` is exactly the type that just
/// failed. `None` covers everything that is not even that: bytes that are not JSON at all, a JSON
/// value that is not an object, or an object whose `id` is missing or not a string.
fn id_of(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct IdOnly {
        id: String,
    }
    serde_json::from_slice::<IdOnly>(body).ok().map(|v| v.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Envelope, Request, Response};

    #[test]
    fn a_message_survives_a_round_trip() {
        let mut buf = Vec::new();
        let envelope = Envelope::new("r1", Request::Status);
        write(&mut buf, &envelope).unwrap();
        let back: Envelope<Request> = read(&mut buf.as_slice()).unwrap();
        assert_eq!(back, envelope);
    }

    #[test]
    fn the_prefix_is_big_endian() {
        let mut buf = Vec::new();
        write(&mut buf, &Envelope::new("r1", Request::Status)).unwrap();
        assert_eq!(
            u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize,
            buf.len() - 4
        );
        // The first byte of a big-endian length under 16 MiB is zero; a little-endian reader
        // would see a length with 0x00 as its *high* byte and a body length in the low bytes.
        assert_eq!(
            buf[0], 0,
            "a short frame's big-endian prefix starts with 0x00"
        );
    }

    #[test]
    fn a_frame_written_for_the_mcp_socket_does_not_parse_here() {
        // `kagisecure_ipc::frame` is little-endian. Rather than depend on it, reproduce exactly
        // what it writes and assert this reader refuses it.
        let body = br#"{"op":"ListVaults"}"#;
        let mut mcp_frame = Vec::new();
        mcp_frame.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        mcp_frame.extend_from_slice(body);
        let err = read::<_, Envelope<Request>>(&mut mcp_frame.as_slice()).unwrap_err();
        assert!(
            matches!(err, FrameError::TooLarge(_)),
            "a little-endian length reads as an enormous big-endian one and is refused up front: {err:?}"
        );
    }

    #[test]
    fn an_oversized_declared_length_is_refused_before_allocating() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            read::<_, Envelope<Request>>(&mut framed.as_slice()),
            Err(FrameError::TooLarge(_))
        ));
    }

    #[test]
    fn several_messages_stream_back_in_order() {
        let mut buf = Vec::new();
        write(
            &mut buf,
            &Envelope::new("a", Response::Status { unlocked: true }),
        )
        .unwrap();
        write(
            &mut buf,
            &Envelope::new("b", Response::Status { unlocked: false }),
        )
        .unwrap();
        let mut cursor = buf.as_slice();
        assert_eq!(read::<_, Envelope<Response>>(&mut cursor).unwrap().id, "a");
        assert_eq!(read::<_, Envelope<Response>>(&mut cursor).unwrap().id, "b");
        assert!(matches!(
            read::<_, Envelope<Response>>(&mut cursor),
            Err(FrameError::Closed)
        ));
    }

    #[test]
    fn a_body_that_fails_to_deserialize_carries_its_id_and_leaves_the_stream_in_sync() {
        // A body that is well-formed JSON, has a correlation id, but does not match `Request` —
        // `Request::Totp` requires `page` and `item_id`, and this has neither.
        let mut buf = Vec::new();
        buf.extend_from_slice(br#"{"ksx":1,"id":"r1","body":{"ask":"totp"}}"#);
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::try_from(buf.len()).unwrap().to_be_bytes());
        framed.extend_from_slice(&buf);
        // A second, well-formed frame right after it, to prove the length prefix already
        // consumed exactly the first frame's bytes and nothing more.
        write(&mut framed, &Envelope::new("r2", Request::Status)).unwrap();

        let mut cursor = framed.as_slice();
        match read::<_, Envelope<Request>>(&mut cursor) {
            Err(FrameError::InvalidBody { id, .. }) => {
                assert_eq!(id.as_deref(), Some("r1"));
            }
            other => panic!("expected InvalidBody with the recovered id, got {other:?}"),
        }
        let next: Envelope<Request> = read(&mut cursor).expect("the next frame is unaffected");
        assert_eq!(next.id, "r2");
    }

    #[test]
    fn a_body_with_no_recoverable_id_reports_none_rather_than_failing() {
        let mut framed = Vec::new();
        let garbage = br#"[1, 2, 3]"#;
        framed.extend_from_slice(&u32::try_from(garbage.len()).unwrap().to_be_bytes());
        framed.extend_from_slice(garbage);
        match read::<_, Envelope<Request>>(&mut framed.as_slice()) {
            Err(FrameError::InvalidBody { id, .. }) => assert_eq!(id, None),
            other => panic!("expected InvalidBody with no id, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_body_is_reported_as_a_close_not_as_garbage() {
        let mut buf = Vec::new();
        write(&mut buf, &Envelope::new("a", Request::Status)).unwrap();
        buf.truncate(buf.len() - 3);
        assert!(matches!(
            read::<_, Envelope<Request>>(&mut buf.as_slice()),
            Err(FrameError::Closed)
        ));
    }

    #[test]
    fn an_empty_stream_reads_as_closed() {
        assert!(matches!(
            read::<_, Envelope<Request>>(&mut [].as_slice()),
            Err(FrameError::Closed)
        ));
    }
}
