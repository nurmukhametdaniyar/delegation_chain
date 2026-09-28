//! Decoder (SPEC §4.4, D-31).
//!
//! One pass. Malformed input fails immediately with a [`DecodeError`]. A
//! canonical-form violation does not stop decoding; the first one is
//! returned alongside the value, so that the verifier can reject it at
//! Algorithm 1 line 5 rather than line 2. [`decode_strict`] rejects both.

use crate::error::{CanonViolation, DecodeError, StrictError};
use crate::value::{Key, Value};
use crate::{MAX_BODY_SIZE, MAX_DEPTH};

/// Decoder limits (D-02, D-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum container nesting; the top-level container is depth 1.
    pub max_depth: usize,
    /// Maximum input length in bytes.
    pub max_size: usize,
}

impl Limits {
    /// Limits for a single body or other protocol structure.
    pub const BODY: Limits = Limits {
        max_depth: MAX_DEPTH,
        max_size: MAX_BODY_SIZE,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Limits::BODY
    }
}

/// Decodes one top-level item. Returns the value and the first canonical-form
/// violation found, if any.
pub fn decode(
    bytes: &[u8],
    limits: Limits,
) -> Result<(Value, Option<CanonViolation>), DecodeError> {
    if bytes.len() > limits.max_size {
        return Err(DecodeError::TooLarge {
            len: bytes.len(),
            limit: limits.max_size,
        });
    }
    let mut d = Decoder {
        buf: bytes,
        pos: 0,
        max_depth: limits.max_depth,
        violation: None,
    };
    let v = d.item(1)?;
    if d.pos != bytes.len() {
        return Err(DecodeError::TrailingBytes(d.pos));
    }
    Ok((v, d.violation))
}

/// Decodes one top-level item, rejecting malformed and non-canonical input
/// alike.
pub fn decode_strict(bytes: &[u8], limits: Limits) -> Result<Value, StrictError> {
    match decode(bytes, limits)? {
        (v, None) => Ok(v),
        (_, Some(violation)) => Err(StrictError::NonCanonical(violation)),
    }
}

const BREAK: u8 = 0xff;

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
    max_depth: usize,
    violation: Option<CanonViolation>,
}

/// A head's argument: a definite value, or the indefinite marker (AI 31).
enum Arg {
    Definite(u64),
    Indefinite,
}

impl<'a> Decoder<'a> {
    fn note(&mut self, v: CanonViolation) {
        if self.violation.is_none() {
            self.violation = Some(v);
        }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or(DecodeError::Truncated(self.pos))?;
        self.pos += 1;
        Ok(b)
    }

    fn peek(&self) -> Result<u8, DecodeError> {
        self.buf
            .get(self.pos)
            .copied()
            .ok_or(DecodeError::Truncated(self.pos))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return Err(DecodeError::Truncated(self.buf.len()));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Reads the argument for additional information `ai` of the head that
    /// started at `start`, noting a non-shortest form.
    fn arg(&mut self, ai: u8, start: usize) -> Result<Arg, DecodeError> {
        let (v, min) = match ai {
            0..=23 => return Ok(Arg::Definite(u64::from(ai))),
            24 => (u64::from(self.byte()?), 24),
            25 => (
                u64::from(u16::from_be_bytes(self.take(2)?.try_into().unwrap())),
                0x100,
            ),
            26 => (
                u64::from(u32::from_be_bytes(self.take(4)?.try_into().unwrap())),
                0x1_0000,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
                0x1_0000_0000,
            ),
            28..=30 => return Err(DecodeError::Reserved(start)),
            _ => return Ok(Arg::Indefinite),
        };
        if v < min {
            self.note(CanonViolation::NonShortest(start));
        }
        Ok(Arg::Definite(v))
    }

    fn definite_len(&self, n: u64, min_item_size: usize) -> Result<usize, DecodeError> {
        // Every element takes at least `min_item_size` bytes, so a length the
        // remaining input cannot hold is truncation; checking before
        // allocating keeps a forged length from reserving memory.
        match usize::try_from(n) {
            Ok(n) if n <= self.remaining() / min_item_size => Ok(n),
            _ => Err(DecodeError::Truncated(self.buf.len())),
        }
    }

    fn enter(&self, depth: usize, start: usize) -> Result<(), DecodeError> {
        if depth > self.max_depth {
            return Err(DecodeError::TooDeep {
                limit: self.max_depth,
                offset: start,
            });
        }
        Ok(())
    }

    fn item(&mut self, depth: usize) -> Result<Value, DecodeError> {
        let start = self.pos;
        let ib = self.byte()?;
        let (major, ai) = (ib >> 5, ib & 0x1f);
        match major {
            0 | 1 => {
                let Arg::Definite(n) = self.arg(ai, start)? else {
                    return Err(DecodeError::IndefiniteInteger(start));
                };
                let n = i128::from(n);
                Ok(Value::Int(if major == 0 { n } else { -1 - n }))
            }
            2 => Ok(Value::Bytes(self.string_body(2, ai, start)?)),
            3 => {
                let raw = self.string_body(3, ai, start)?;
                String::from_utf8(raw)
                    .map(Value::Text)
                    .map_err(|_| DecodeError::InvalidUtf8(start))
            }
            4 => {
                self.enter(depth, start)?;
                let mut items = Vec::new();
                match self.arg(ai, start)? {
                    Arg::Definite(n) => {
                        let n = self.definite_len(n, 1)?;
                        items.reserve(n);
                        for _ in 0..n {
                            items.push(self.item(depth + 1)?);
                        }
                    }
                    Arg::Indefinite => {
                        self.note(CanonViolation::Indefinite(start));
                        while self.peek()? != BREAK {
                            items.push(self.item(depth + 1)?);
                        }
                        self.pos += 1;
                    }
                }
                Ok(Value::Array(items))
            }
            5 => {
                self.enter(depth, start)?;
                let mut entries: Vec<(Key, Value)> = Vec::new();
                let mut sorted = true;
                let mut push =
                    |d: &mut Self, entries: &mut Vec<(Key, Value)>| -> Result<(), DecodeError> {
                        let key_start = d.pos;
                        let k = d.key()?;
                        if let Some((prev, _)) = entries.last() {
                            match prev.cmp(&k) {
                                std::cmp::Ordering::Less => {}
                                std::cmp::Ordering::Equal => {
                                    return Err(DecodeError::DuplicateKey(key_start));
                                }
                                std::cmp::Ordering::Greater => {
                                    sorted = false;
                                    d.note(CanonViolation::UnsortedKeys(key_start));
                                }
                            }
                        }
                        let v = d.item(depth + 1)?;
                        entries.push((k, v));
                        Ok(())
                    };
                match self.arg(ai, start)? {
                    Arg::Definite(n) => {
                        let n = self.definite_len(n, 2)?;
                        entries.reserve(n);
                        for _ in 0..n {
                            push(self, &mut entries)?;
                        }
                    }
                    Arg::Indefinite => {
                        self.note(CanonViolation::Indefinite(start));
                        while self.peek()? != BREAK {
                            push(self, &mut entries)?;
                        }
                        self.pos += 1;
                    }
                }
                if !sorted {
                    // Adjacent comparison only catches duplicates in sorted
                    // input; unsorted input needs a full check.
                    let mut keys: Vec<&Key> = entries.iter().map(|(k, _)| k).collect();
                    keys.sort();
                    if keys.windows(2).any(|w| w[0] == w[1]) {
                        return Err(DecodeError::DuplicateKey(start));
                    }
                }
                Ok(Value::Map(entries))
            }
            6 => Err(DecodeError::Tag(start)),
            _ => match ai {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                25..=27 => Err(DecodeError::Float(start)),
                28..=30 => Err(DecodeError::Reserved(start)),
                31 => Err(DecodeError::UnexpectedBreak(start)),
                _ => Err(DecodeError::Simple(start)),
            },
        }
    }

    /// Reads the payload of a byte string (major 2) or text string (major 3),
    /// definite or chunked. UTF-8 is checked per chunk here and on the whole by
    /// the caller.
    fn string_body(&mut self, major: u8, ai: u8, start: usize) -> Result<Vec<u8>, DecodeError> {
        match self.arg(ai, start)? {
            Arg::Definite(n) => Ok(self.take(self.definite_len(n, 1)?)?.to_vec()),
            Arg::Indefinite => {
                self.note(CanonViolation::Indefinite(start));
                let mut out = Vec::new();
                loop {
                    let chunk_start = self.pos;
                    let ib = self.byte()?;
                    if ib == BREAK {
                        return Ok(out);
                    }
                    if ib >> 5 != major {
                        return Err(DecodeError::BadChunk(chunk_start));
                    }
                    let Arg::Definite(n) = self.arg(ib & 0x1f, chunk_start)? else {
                        return Err(DecodeError::BadChunk(chunk_start));
                    };
                    let chunk = self.take(self.definite_len(n, 1)?)?;
                    if major == 3 && std::str::from_utf8(chunk).is_err() {
                        return Err(DecodeError::InvalidUtf8(chunk_start));
                    }
                    out.extend_from_slice(chunk);
                }
            }
        }
    }

    fn key(&mut self) -> Result<Key, DecodeError> {
        let start = self.pos;
        let ib = self.byte()?;
        let (major, ai) = (ib >> 5, ib & 0x1f);
        match major {
            0 => match self.arg(ai, start)? {
                Arg::Definite(n) => Ok(Key::Uint(n)),
                Arg::Indefinite => Err(DecodeError::IndefiniteInteger(start)),
            },
            3 => {
                let raw = self.string_body(3, ai, start)?;
                String::from_utf8(raw)
                    .map(Key::Text)
                    .map_err(|_| DecodeError::InvalidUtf8(start))
            }
            _ => Err(DecodeError::KeyType(start)),
        }
    }
}
