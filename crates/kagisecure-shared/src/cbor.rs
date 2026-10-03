//! Deterministic CBOR for everything this crate signs, hashes or compares as bytes.
//!
//! Every structure a signature or a hash covers is written in RFC 8949 §4.2.1's core
//! deterministic encoding: the shortest form of every integer and length, definite lengths only,
//! and every map's keys in the bytewise order of their own encodings, with no key twice. And a
//! reader **refuses** anything else rather than normalising it: two readers that disagree about
//! what a signed byte string says — a duplicated key read as its first value by one and its last
//! by another, say — is how a signature comes to vouch for two different things.
//!
//! # Scanned before it is decoded
//!
//! Before `ciborium` decodes a byte of it, the input is **scanned** ([`scan`]): walked head by
//! head, in one linear pass, without decoding or copying any content — so nothing secret in a
//! payload is copied, and nothing is allocated for a length the input does not actually hold.
//! The scan refuses what is not exactly one well-formed item: a length or count larger than what
//! is left, an indefinite length (bar the one exception [`Strictness::WellFormed`] allows), a
//! head not in its shortest form, a reserved or unsupported
//! simple value, nesting deeper than [`MAX_DEPTH`], a map with the same key twice, anything after
//! the item — and, for [`Strictness::Deterministic`], a map whose keys are not in strictly
//! increasing bytewise order. What it leaves over (the shortest float, say) is caught by
//! decoding, re-encoding and requiring the same bytes back: `ciborium` always writes the shortest
//! form, so anything a non-deterministic writer could vary changes the re-encoding.
//!
//! The scan also hands back a top-level map's entries as the byte ranges they occupy
//! ([`scan_map`]), which is how a limit on a field — a record's `parents` and `roster` heads —
//! is counted from the encoded bytes before the body is decoded at all (ADR-0035 addendum,
//! "Limits").

use ciborium::Value;

use crate::error::{Result, SharedError};

/// Encode `value` exactly as it is. Callers build their maps with [`map`], which sorts them.
pub(crate) fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    // Writing a `Value` into a `Vec` cannot fail: there is no I/O error and no unsupported type.
    ciborium::into_writer(value, &mut out).expect("encoding a CBOR value into memory");
    out
}

/// The deterministic encoding of one map key, for ordering.
fn key_bytes(key: &Value) -> Vec<u8> {
    encode(key)
}

/// A map with its entries in deterministic order.
///
/// # Panics
///
/// If two entries have the same key: the callers build maps from fixed, distinct key names, so
/// a duplicate is a bug in this crate, never a property of input.
pub(crate) fn map(entries: Vec<(Value, Value)>) -> Value {
    let mut keyed: Vec<(Vec<u8>, (Value, Value))> = entries
        .into_iter()
        .map(|entry| (key_bytes(&entry.0), entry))
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    for pair in keyed.windows(2) {
        assert!(
            pair[0].0 != pair[1].0,
            "a map this crate builds has a duplicate key"
        );
    }
    Value::Map(keyed.into_iter().map(|(_, entry)| entry).collect())
}

/// The deepest nesting of arrays, maps and tags any input may have. Nothing this format writes
/// comes close; deeper input is refused by the scan, before a recursive decoder sees it.
pub(crate) const MAX_DEPTH: usize = 64;

/// How strictly [`scan`] reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Strictness {
    /// RFC 8949 §4.2.1's core deterministic encoding: everything [`Self::WellFormed`] requires,
    /// and every map's keys in strictly increasing bytewise order. For everything this format
    /// signs, hashes or compares as bytes.
    Deterministic,
    /// One well-formed item with heads in their shortest form, no key twice in any map and
    /// nothing after it, with map keys in whatever order the writer chose and an array or map
    /// allowed an indefinite length (strings never are). For an item or environment payload's
    /// plaintext, which `serde` writes in field order — and, for a struct with a flattened
    /// field, as an indefinite-length map.
    WellFormed,
}

const SCAN_SHAPE: &str = "not one well-formed CBOR item within bounds";

/// One pass over encoded CBOR (module documentation).
struct Scanner<'a> {
    bytes: &'a [u8],
    pos: usize,
    strictness: Strictness,
}

impl<'a> Scanner<'a> {
    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, len: u64) -> Result<&'a [u8]> {
        let len = usize::try_from(len).map_err(|_| SharedError::Malformed(SCAN_SHAPE))?;
        if len > self.remaining() {
            return Err(SharedError::Malformed(SCAN_SHAPE));
        }
        let taken = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(taken)
    }

    /// A head: its major type and argument, the argument in its shortest form. Major type 7's
    /// argument is returned as the additional information, with the float's bytes skipped.
    fn head(&mut self) -> Result<(u8, u64)> {
        let first = self.take(1)?[0];
        let major = first >> 5;
        let info = first & 0x1f;
        if major == 7 {
            match info {
                // false, true, null, undefined.
                20..=23 => {}
                // Half, single and double floats: their shortest form is the re-encoding's
                // check.
                25 => {
                    self.take(2)?;
                }
                26 => {
                    self.take(4)?;
                }
                27 => {
                    self.take(8)?;
                }
                // Unassigned simple values, a one-byte simple value, the reserved values and a
                // "break" with nothing indefinite to end: none is anything this format writes.
                _ => return Err(SharedError::Malformed(SCAN_SHAPE)),
            }
            return Ok((7, u64::from(info)));
        }
        let (value, shortest_from) = match info {
            0..=23 => return Ok((major, u64::from(info))),
            24 => (u64::from(self.take(1)?[0]), 24),
            25 => (
                u64::from(u16::from_be_bytes(
                    self.take(2)?.try_into().expect("two bytes"),
                )),
                1 << 8,
            ),
            26 => (
                u64::from(u32::from_be_bytes(
                    self.take(4)?.try_into().expect("four bytes"),
                )),
                1 << 16,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().expect("eight bytes")),
                1 << 32,
            ),
            // Reserved, or indefinite length: neither is deterministic, and neither is written
            // here.
            _ => return Err(SharedError::Malformed(SCAN_SHAPE)),
        };
        if value < shortest_from {
            return Err(SharedError::Malformed(SCAN_SHAPE));
        }
        Ok((major, value))
    }

    /// Skip one item, checking it; returns the byte range it occupied.
    fn item(&mut self, depth: usize) -> Result<&'a [u8]> {
        if depth > MAX_DEPTH {
            return Err(SharedError::Malformed(
                "CBOR nested deeper than this format allows",
            ));
        }
        let start = self.pos;
        if self.strictness == Strictness::WellFormed {
            match self.bytes.get(self.pos) {
                // An indefinite-length array or map: items up to a "break".
                Some(0x9f) => {
                    self.pos += 1;
                    while !self.at_break()? {
                        self.item(depth + 1)?;
                    }
                    return Ok(&self.bytes[start..self.pos]);
                }
                Some(0xbf) => {
                    self.pos += 1;
                    self.map_entries(None, depth, |_, _| Ok(()))?;
                    return Ok(&self.bytes[start..self.pos]);
                }
                _ => {}
            }
        }
        let (major, argument) = self.head()?;
        match major {
            0 | 1 | 7 => {}
            2 => {
                self.take(argument)?;
            }
            3 => {
                let text = self.take(argument)?;
                if std::str::from_utf8(text).is_err() {
                    return Err(SharedError::Malformed(SCAN_SHAPE));
                }
            }
            4 => {
                // Every item is at least one byte: a count above what is left is refused
                // before a single item is read.
                if argument > self.remaining() as u64 {
                    return Err(SharedError::Malformed(SCAN_SHAPE));
                }
                for _ in 0..argument {
                    self.item(depth + 1)?;
                }
            }
            5 => {
                self.map_entries(Some(argument), depth, |_, _| Ok(()))?;
            }
            6 => {
                self.item(depth + 1)?;
            }
            _ => unreachable!("a major type is three bits"),
        }
        Ok(&self.bytes[start..self.pos])
    }

    /// Whether the next byte is a "break", consuming it if so.
    fn at_break(&mut self) -> Result<bool> {
        match self.bytes.get(self.pos) {
            None => Err(SharedError::Malformed(SCAN_SHAPE)),
            Some(0xff) => {
                self.pos += 1;
                Ok(true)
            }
            Some(_) => Ok(false),
        }
    }

    /// Skip a map's `count` entries — or, for `None`, entries up to a "break" — checking their
    /// keys, handing each entry's key and value ranges to `each`.
    fn map_entries(
        &mut self,
        count: Option<u64>,
        depth: usize,
        mut each: impl FnMut(&'a [u8], &'a [u8]) -> Result<()>,
    ) -> Result<()> {
        // Every entry is at least two bytes.
        if count.is_some_and(|count| count > (self.remaining() / 2) as u64) {
            return Err(SharedError::Malformed(SCAN_SHAPE));
        }
        let mut keys: Vec<&'a [u8]> = Vec::new();
        let mut read = 0u64;
        loop {
            match count {
                Some(count) if read == count => break,
                Some(_) => {}
                None if self.at_break()? => break,
                None => {}
            }
            read += 1;
            let key = self.item(depth + 1)?;
            let value = self.item(depth + 1)?;
            match self.strictness {
                Strictness::Deterministic => {
                    // Strictly increasing, so no key twice either. Only the previous key is
                    // kept: the check is linear in the map's size.
                    if keys.last().is_some_and(|previous| *previous >= key) {
                        return Err(SharedError::Malformed(
                            "a CBOR map's keys are out of order or repeated",
                        ));
                    }
                    keys.clear();
                    keys.push(key);
                }
                Strictness::WellFormed => keys.push(key),
            }
            each(key, value)?;
        }
        if self.strictness == Strictness::WellFormed {
            keys.sort_unstable();
            if keys.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(SharedError::Malformed("a CBOR map has the same key twice"));
            }
        }
        Ok(())
    }

    fn finish(&self) -> Result<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(SharedError::Malformed(
                "not in deterministic CBOR encoding, or followed by extra bytes",
            ))
        }
    }
}

/// Check that `bytes` is exactly one CBOR item under `strictness`, without decoding or copying
/// any of its content (module documentation).
///
/// # Errors
///
/// [`SharedError::Malformed`] for anything else.
pub(crate) fn scan(bytes: &[u8], strictness: Strictness) -> Result<()> {
    let mut scanner = Scanner {
        bytes,
        pos: 0,
        strictness,
    };
    scanner.item(0)?;
    scanner.finish()
}

/// [`scan`] `bytes`, deterministically, as one map, and return its entries as the byte ranges
/// of their keys and values — for counting a field before the map is decoded.
///
/// # Errors
///
/// [`SharedError::Malformed`] for anything that is not one map in deterministic encoding.
pub(crate) fn scan_map<'a>(
    bytes: &'a [u8],
    what: &'static str,
) -> Result<Vec<(&'a [u8], &'a [u8])>> {
    let mut scanner = Scanner {
        bytes,
        pos: 0,
        strictness: Strictness::Deterministic,
    };
    let (major, count) = scanner.head()?;
    if major != 5 {
        return Err(SharedError::Malformed(what));
    }
    let mut entries = Vec::new();
    scanner.map_entries(Some(count), 0, |key, value| {
        entries.push((key, value));
        Ok(())
    })?;
    scanner.finish()?;
    Ok(entries)
}

/// [`scan`] `bytes` as one well-formed map — definite or indefinite, keys in any order, no key
/// twice — and return its entries as the byte ranges of their keys and values. For taking a
/// `serde`-encoded item or environment apart without decoding, or copying, its values.
///
/// # Errors
///
/// [`SharedError::Malformed`] for anything that is not one such map.
pub(crate) fn well_formed_map_entries<'a>(
    bytes: &'a [u8],
    what: &'static str,
) -> Result<Vec<(&'a [u8], &'a [u8])>> {
    let mut scanner = Scanner {
        bytes,
        pos: 0,
        strictness: Strictness::WellFormed,
    };
    let mut entries = Vec::new();
    let count = if bytes.first() == Some(&0xbf) {
        scanner.pos = 1;
        None
    } else {
        match scanner.head()? {
            (5, count) => Some(count),
            _ => return Err(SharedError::Malformed(what)),
        }
    };
    scanner.map_entries(count, 0, |key, value| {
        entries.push((key, value));
        Ok(())
    })?;
    scanner.finish()?;
    Ok(entries)
}

/// [`scan`] `bytes` as one well-formed array — definite or indefinite — and return its items as
/// the byte ranges they occupy.
///
/// # Errors
///
/// [`SharedError::Malformed`] for anything that is not one such array.
pub(crate) fn well_formed_array_items<'a>(
    bytes: &'a [u8],
    what: &'static str,
) -> Result<Vec<&'a [u8]>> {
    let mut scanner = Scanner {
        bytes,
        pos: 0,
        strictness: Strictness::WellFormed,
    };
    let mut items = Vec::new();
    if bytes.first() == Some(&0x9f) {
        scanner.pos = 1;
        while !scanner.at_break()? {
            items.push(scanner.item(1)?);
        }
    } else {
        let (4, count) = scanner.head()? else {
            return Err(SharedError::Malformed(what));
        };
        if count > scanner.remaining() as u64 {
            return Err(SharedError::Malformed(what));
        }
        for _ in 0..count {
            items.push(scanner.item(1)?);
        }
    }
    scanner.finish()?;
    Ok(items)
}

/// Write a CBOR head of major type `major` with argument `value`, in its shortest form.
pub(crate) fn write_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let major = major << 5;
    match value {
        0..=23 => out.push(major | u8::try_from(value).expect("below 24")),
        24..=0xff => {
            out.push(major | 24);
            out.push(u8::try_from(value).expect("one byte"));
        }
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&u16::try_from(value).expect("two bytes").to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend_from_slice(&u32::try_from(value).expect("four bytes").to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

/// The length of the head [`write_head`] writes.
pub(crate) const fn head_len(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// The number of items in the encoded array `item`, read from its head alone; `None` if it is
/// not an array. Only for bytes [`scan`] has already checked.
pub(crate) fn array_len(item: &[u8]) -> Option<u64> {
    let mut scanner = Scanner {
        bytes: item,
        pos: 0,
        strictness: Strictness::Deterministic,
    };
    match scanner.head() {
        Ok((4, count)) => Some(count),
        _ => None,
    }
}

/// Whether the encoded key `key` is the text `name`.
pub(crate) fn is_text_key(key: &[u8], name: &str) -> bool {
    key == encode(&text(name)).as_slice()
}

/// Decode `bytes` as exactly one CBOR item in deterministic encoding.
///
/// The caller bounds `bytes` first; this reads nothing beyond them, and scans them (module
/// documentation) before decoding.
///
/// # Errors
///
/// [`SharedError::Malformed`] for anything that is not one CBOR item, or is one that a
/// deterministic writer would have written differently.
pub(crate) fn decode_canonical(bytes: &[u8]) -> Result<Value> {
    scan(bytes, Strictness::Deterministic)?;
    decode_scanned(bytes)
}

/// Decode bytes [`scan`] has already checked as deterministic, and confirm the re-encoding is
/// the same bytes.
pub(crate) fn decode_scanned(bytes: &[u8]) -> Result<Value> {
    let value: Value =
        ciborium::from_reader(bytes).map_err(|_| SharedError::Malformed("not valid CBOR"))?;
    if encode(&value) != bytes {
        return Err(SharedError::Malformed(
            "not in deterministic CBOR encoding, or followed by extra bytes",
        ));
    }
    Ok(value)
}

/// A text key, for building and reading maps.
pub(crate) fn text(key: &str) -> Value {
    Value::Text(key.to_owned())
}

/// A byte string.
pub(crate) fn bytes(data: &[u8]) -> Value {
    Value::Bytes(data.to_vec())
}

/// Read a CBOR map with text keys into its entries, refusing any other shape.
pub(crate) fn text_map(value: Value, what: &'static str) -> Result<Vec<(String, Value)>> {
    let Value::Map(entries) = value else {
        return Err(SharedError::Malformed(what));
    };
    entries
        .into_iter()
        .map(|(k, v)| match k {
            Value::Text(k) => Ok((k, v)),
            _ => Err(SharedError::Malformed(what)),
        })
        .collect()
}

/// A byte string of exactly `N` bytes.
pub(crate) fn fixed_bytes<const N: usize>(value: &Value, what: &'static str) -> Result<[u8; N]> {
    match value {
        Value::Bytes(b) => b
            .as_slice()
            .try_into()
            .map_err(|_| SharedError::Malformed(what)),
        _ => Err(SharedError::Malformed(what)),
    }
}

/// An unsigned integer that fits in a `u64`.
pub(crate) fn uint(value: &Value, what: &'static str) -> Result<u64> {
    match value {
        Value::Integer(i) => u64::try_from(*i).map_err(|_| SharedError::Malformed(what)),
        _ => Err(SharedError::Malformed(what)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_map_is_written_in_the_order_of_its_encoded_keys() {
        // Shorter text keys first (their header byte is smaller), then bytewise.
        let value = map(vec![
            (text("sig_pk"), Value::Integer(3.into())),
            (text("suite"), Value::Integer(1.into())),
            (text("kem_pk"), Value::Integer(2.into())),
        ]);
        let Value::Map(entries) = &value else {
            unreachable!()
        };
        let keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_text().unwrap()).collect();
        assert_eq!(keys, ["suite", "kem_pk", "sig_pk"]);
        assert_eq!(decode_canonical(&encode(&value)).unwrap(), value);
    }

    #[test]
    fn a_non_deterministic_encoding_is_refused() {
        // {"a": 1} written properly, then four ways a lax writer could vary it.
        assert!(decode_canonical(&[0xa1, 0x61, b'a', 0x01]).is_ok());
        let refused: [&[u8]; 6] = [
            // The integer 1 in a two-byte form.
            &[0xa1, 0x61, b'a', 0x18, 0x01],
            // The key's length in a longer form.
            &[0xa1, 0x78, 0x01, b'a', 0x01],
            // An indefinite-length map.
            &[0xbf, 0x61, b'a', 0x01, 0xff],
            // Trailing bytes.
            &[0xa1, 0x61, b'a', 0x01, 0x00],
            // Keys out of order: {"b": 1, "a": 2}.
            &[0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02],
            // The same key twice.
            &[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02],
        ];
        for bytes in refused {
            assert!(
                matches!(decode_canonical(bytes), Err(SharedError::Malformed(_))),
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn the_scan_refuses_what_a_decoder_should_never_see() {
        let mut deep = vec![0x81; MAX_DEPTH + 1];
        deep.push(0x00);
        let mut deep_enough = vec![0x81; MAX_DEPTH];
        deep_enough.push(0x00);
        assert!(scan(&deep_enough, Strictness::Deterministic).is_ok());
        let refused: [&[u8]; 9] = [
            &deep,
            // An array claiming 2^64 − 1 items, and a map claiming more entries than bytes left.
            &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00],
            &[0xa2, 0x00, 0x00],
            // A byte string longer than what is left.
            &[0x5a, 0x00, 0x10, 0x00, 0x00, 0x00],
            // An indefinite-length byte string, a lone "break", an unassigned simple value and a
            // one-byte simple value.
            &[0x5f, 0x41, 0x00, 0xff],
            &[0xff],
            &[0xe0],
            &[0xf8, 0x20],
            // Text that is not UTF-8.
            &[0x61, 0xff],
        ];
        for bytes in refused {
            for strictness in [Strictness::Deterministic, Strictness::WellFormed] {
                assert!(
                    matches!(scan(bytes, strictness), Err(SharedError::Malformed(_))),
                    "{bytes:02x?}"
                );
            }
        }
    }

    #[test]
    fn well_formed_allows_any_key_order_but_never_a_key_twice() {
        // {"b": 1, "a": 2}: out of order, which a serde writer may produce.
        let unsorted = [0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02];
        assert!(scan(&unsorted, Strictness::WellFormed).is_ok());
        assert!(scan(&unsorted, Strictness::Deterministic).is_err());
        // {"a": 1, "b": 2, "a": 3}, and the same one level down.
        let twice = [0xa3, 0x61, b'a', 0x01, 0x61, b'b', 0x02, 0x61, b'a', 0x03];
        let nested = [0x81, 0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02];
        for bytes in [&twice[..], &nested[..]] {
            assert!(scan(bytes, Strictness::WellFormed).is_err(), "{bytes:02x?}");
        }
        // An indefinite-length map, as serde writes a struct with a flattened field, is
        // well-formed but not deterministic — and still may not repeat a key or run off the end.
        let indefinite = [0xbf, 0x61, b'b', 0x01, 0x61, b'a', 0x9f, 0x02, 0xff, 0xff];
        assert!(scan(&indefinite, Strictness::WellFormed).is_ok());
        assert!(scan(&indefinite, Strictness::Deterministic).is_err());
        let refused: [&[u8]; 3] = [
            &[0xbf, 0x61, b'a', 0x01, 0x61, b'a', 0x02, 0xff],
            &[0xbf, 0x61, b'a', 0x01],
            &[0x9f, 0x01],
        ];
        for bytes in refused {
            assert!(scan(bytes, Strictness::WellFormed).is_err(), "{bytes:02x?}");
        }
        // A head in a longer form, and trailing bytes, are refused in either mode.
        assert!(scan(&[0x18, 0x01], Strictness::WellFormed).is_err());
        assert!(scan(&[0x01, 0x00], Strictness::WellFormed).is_err());
    }

    #[test]
    fn a_map_is_scanned_into_the_ranges_of_its_entries() {
        let value = map(vec![
            (text("parents"), Value::Array(vec![Value::Null; 3])),
            (text("v"), Value::Integer(1.into())),
        ]);
        let bytes = encode(&value);
        let entries = scan_map(&bytes, "a map").unwrap();
        assert_eq!(entries.len(), 2);
        assert!(is_text_key(entries[0].0, "v"));
        assert_eq!(array_len(entries[0].1), None);
        assert!(is_text_key(entries[1].0, "parents"));
        assert_eq!(array_len(entries[1].1), Some(3));
        assert!(scan_map(&encode(&Value::Array(vec![])), "a map").is_err());
    }

    #[test]
    fn a_truncated_or_empty_input_is_refused() {
        assert!(decode_canonical(&[]).is_err());
        assert!(decode_canonical(&[0xa1, 0x61]).is_err());
        assert!(decode_canonical(&[0x58, 0x20, 0x00]).is_err());
    }

    #[test]
    #[should_panic(expected = "duplicate key")]
    fn building_a_map_with_a_duplicate_key_is_a_bug() {
        let _ = map(vec![
            (text("a"), Value::Null),
            (text("a"), Value::Bool(true)),
        ]);
    }
}
