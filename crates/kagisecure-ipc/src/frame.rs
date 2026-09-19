//! Framing: `u32` little-endian length, then that many bytes of UTF-8 JSON.
//!
//! architecture.md §4.2 chose this over a binary codec deliberately: the traffic is a handful of
//! messages per tool call, and a human-readable frame keeps the security-critical path auditable
//! with `nc` and `xxd`. The 1 MiB cap is what stops a hostile peer from asking us to allocate a
//! gigabyte before we have read a single valid byte.

use std::io::{Read, Write};

/// Largest frame either side will send or accept.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Length prefix width.
const PREFIX: usize = 4;

/// What can go wrong on the wire.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// The peer closed the connection.
    #[error("the connection was closed")]
    Closed,
    /// The declared length exceeds [`MAX_FRAME`].
    #[error("frame of {0} bytes exceeds the {MAX_FRAME}-byte limit")]
    TooLarge(usize),
    /// The frame body was not valid JSON for the expected message type.
    #[error("malformed message: {0}")]
    Malformed(String),
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
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Read one frame and deserialize it.
///
/// # Errors
///
/// [`FrameError::Closed`] on a clean end of stream, [`FrameError::TooLarge`] for an oversized
/// declared length, [`FrameError::Malformed`] for a body that does not parse, or any I/O failure.
pub fn read<R: Read, T: serde::de::DeserializeOwned>(r: &mut R) -> Result<T, FrameError> {
    let mut prefix = [0u8; PREFIX];
    match r.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(e) => return Err(FrameError::Io(e)),
    }
    let len = u32::from_le_bytes(prefix) as usize;
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
    serde_json::from_slice(&body).map_err(|e| FrameError::Malformed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ErrorCode, Request, Response};

    #[test]
    fn a_message_survives_a_round_trip() {
        let mut buf = Vec::new();
        write(&mut buf, &Request::ListVaults).unwrap();
        let back: Request = read(&mut buf.as_slice()).unwrap();
        assert_eq!(back, Request::ListVaults);
    }

    #[test]
    fn several_messages_stream_back_in_order() {
        let mut buf = Vec::new();
        write(&mut buf, &Response::Locked).unwrap();
        write(
            &mut buf,
            &Response::error(ErrorCode::UserDenied, "The user declined."),
        )
        .unwrap();
        let mut cursor = buf.as_slice();
        assert_eq!(read::<_, Response>(&mut cursor).unwrap(), Response::Locked);
        assert!(matches!(
            read::<_, Response>(&mut cursor).unwrap(),
            Response::Error {
                code: ErrorCode::UserDenied,
                ..
            }
        ));
        assert!(matches!(
            read::<_, Response>(&mut cursor),
            Err(FrameError::Closed)
        ));
    }

    #[test]
    fn the_prefix_is_little_endian_and_the_body_is_json() {
        let mut buf = Vec::new();
        write(&mut buf, &Request::ListVaults).unwrap();
        let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(len, buf.len() - 4);
        assert_eq!(
            std::str::from_utf8(&buf[4..]).unwrap(),
            r#"{"op":"ListVaults"}"#
        );
    }

    #[test]
    fn an_oversized_declared_length_is_refused_before_allocating() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::MAX.to_le_bytes());
        let err = read::<_, Request>(&mut framed.as_slice()).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(_)));
    }

    #[test]
    fn a_truncated_body_is_reported_as_a_close_not_as_garbage() {
        let mut buf = Vec::new();
        write(&mut buf, &Request::ListVaults).unwrap();
        buf.truncate(buf.len() - 3);
        assert!(matches!(
            read::<_, Request>(&mut buf.as_slice()),
            Err(FrameError::Closed)
        ));
    }

    #[test]
    fn garbage_inside_a_well_formed_frame_is_a_parse_error() {
        let body = br#"{"op":"NoSuchOperation"}"#;
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(body);
        assert!(matches!(
            read::<_, Request>(&mut buf.as_slice()),
            Err(FrameError::Malformed(_))
        ));
    }

    #[test]
    fn an_empty_stream_reads_as_closed() {
        assert!(matches!(
            read::<_, Request>(&mut [].as_slice()),
            Err(FrameError::Closed)
        ));
    }
}
