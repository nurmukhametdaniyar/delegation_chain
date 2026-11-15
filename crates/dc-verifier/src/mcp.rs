//! The MCP binding (SPEC §10.6; D-104, ahead of the paper: P-36).
//!
//! An MCP tool invocation is a JSON-RPC `tools/call` request. The chain
//! travels in `params._meta` under [`META_KEY`], as unpadded base64url over
//! the envelope's canonical encoding. B_N's tool is `params.name`, its
//! action the constant [`ACTION`], and its parameter map `params.arguments`
//! under the mapping below. [`Verifier::verify_mcp_call`] checks all three
//! against B_N before it runs Algorithms 1 and 2, which are unchanged, so a
//! request whose tool, action or arguments differ from what the chain binds
//! costs no signature check and consumes no nonce.
//!
//! The request is read by the strict parser below rather than a JSON
//! library, which would keep the last of two equal keys, read `1.0` as 1, or
//! read −2⁶⁴ as a float. A request is malformed if it is larger than
//! [`MAX_REQUEST_SIZE`] or is not RFC 8259 JSON, or if it holds anywhere
//! - a number that is not an integer literal without a fraction or exponent
//!   in [−2⁶⁴, 2⁶⁴ − 1], or is `-0`;
//! - a string or key that is not NFC (never normalized);
//! - a lone surrogate, or bytes that are not UTF-8;
//! - two equal keys in one object (compared after unescaping);
//! - a container deeper than [`MAX_REQUEST_DEPTH`].
//!
//! Rejections are typed ([`McpReject`]). The binding assigns no JSON-RPC
//! error codes and integrates no MCP SDK.

use dc_cbor::nfc::is_nfc_str;
use dc_cbor::{INT_MAX, INT_MIN, Key, MAX_BODY_SIZE, MAX_DEPTH, Value, encode};
use dc_crypto::{ChainScheme, ops};
use dc_registry::{PolicyStore, Resolver};
use dc_types::{Body, Clock, ENVELOPE_LIMITS, Envelope, decode_body};
use thiserror::Error;

use crate::{Accepted, OpCounts, Reject, Verifier};

/// The `_meta` key that carries the chain (D-104, D1). A reverse-DNS prefix
/// in the format of the MCP specification, revision 2026-07-28.
pub const META_KEY: &str = "io.github.nurmukhametdaniyar/delegationchain";

/// B_N's action for every invocation made over MCP (D-104, D2).
pub const ACTION: &str = "call";

/// The deepest container a request may hold, the request object being at
/// depth 1. The arguments object is at depth 3 in the request and, as B_N's
/// parameter map, at depth 2 in B_N, so this is D-02's limit of 16 on B_N:
/// the arguments may nest 15 levels, themselves included.
pub const MAX_REQUEST_DEPTH: usize = MAX_DEPTH + 1;

/// The largest request, in bytes, checked before parsing: the largest
/// envelope in base64url, six bytes of JSON for every byte of the largest
/// canonical arguments (a `\uXXXX` escape for a one-byte character, or
/// `false,` for one byte of CBOR), and 64 KiB for everything else.
pub const MAX_REQUEST_SIZE: usize =
    (ENVELOPE_LIMITS.max_size * 4).div_ceil(3) + 6 * MAX_BODY_SIZE + 64 * 1024;

/// Why a request is malformed. `at` is a byte offset into the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum Malformed {
    #[error("{len} bytes, more than {}", MAX_REQUEST_SIZE)]
    TooLarge { len: usize },
    #[error("not JSON at byte {at}: {what}")]
    Syntax { at: usize, what: &'static str },
    #[error("byte {at}: a number that is not an integer literal in [-2^64, 2^64 - 1]")]
    Number { at: usize },
    #[error("byte {at}: invalid Unicode (bytes that are not UTF-8, or a lone surrogate)")]
    InvalidUnicode { at: usize },
    #[error("byte {at}: a string or key that is not NFC")]
    NotNfc { at: usize },
    #[error("byte {at}: an object with two equal keys")]
    DuplicateKey { at: usize },
    #[error("byte {at}: a container deeper than {}", MAX_REQUEST_DEPTH)]
    TooDeep { at: usize },
    #[error("{0}")]
    Shape(&'static str),
    #[error(
        "the arguments' canonical encoding is {len} bytes, more than {}",
        MAX_BODY_SIZE
    )]
    ArgumentsTooLarge { len: usize },
}

/// Why the binding rejected a request (SPEC §10.6). Every variant but the
/// last is decided before Algorithms 1 and 2 run.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum McpReject {
    #[error("malformed request: {0}")]
    Malformed(#[from] Malformed),
    #[error("the method is not tools/call")]
    NotToolsCall,
    #[error("params._meta carries no chain under {}", META_KEY)]
    MissingChain,
    #[error("the chain is not strict unpadded base64url: {0}")]
    ChainEncoding(&'static str),
    #[error("the chain has no readable invocation body: {0}")]
    NoInvocation(String),
    #[error("B_N's tool is not params.name")]
    ToolMismatch,
    #[error("B_N's action is not `call`")]
    ActionNotCall,
    #[error("Canon(arguments) differs from Canon(B_N.params)")]
    ArgumentsMismatch,
    #[error("rejected by Verify: {0}")]
    Verify(Reject),
}

/// A `tools/call` request as the binding reads it: steps 1–3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolsCall {
    /// `params.name`.
    pub name: String,
    /// `params.arguments` as a parameter map; the empty map when absent.
    pub arguments: Value,
    /// `Canon(arguments)`.
    pub canonical_arguments: Vec<u8>,
    /// The envelope's bytes, decoded from [`META_KEY`].
    pub chain: Vec<u8>,
}

impl<C: ChainScheme, R: Resolver, P: PolicyStore, K: Clock> Verifier<C, R, P, K> {
    /// Verifies an MCP `tools/call` request at time `t`: parses it and
    /// decodes the chain ([`read_tools_call`]), checks B_N's tool, action and
    /// parameters against it, then runs Algorithms 1 and 2 on the chain.
    pub fn verify_mcp_call(&self, request: &[u8], t: u64) -> Result<Accepted, McpReject> {
        let call = read_tools_call(request)?;
        bind::<C>(&call)?;
        self.verify_at(&call.chain, t).map_err(McpReject::Verify)
    }

    /// [`Self::verify_mcp_call`] with this call's operation counts (feature
    /// `count-ops`; zeros otherwise).
    pub fn verify_mcp_call_counted(
        &self,
        request: &[u8],
        t: u64,
    ) -> (Result<Accepted, McpReject>, OpCounts) {
        ops::reset();
        let r = self.verify_mcp_call(request, t);
        (r, ops::snapshot())
    }
}

/// Step 4: B_N's tool, action and parameters against the request, each with
/// its own reason. A chain whose envelope or last body does not decode as
/// an invocation body has nothing to compare; Verify would reject it at
/// line 2 or 7.
fn bind<C: ChainScheme>(call: &ToolsCall) -> Result<(), McpReject> {
    let unreadable = |e: &dyn std::fmt::Display| McpReject::NoInvocation(e.to_string());
    let env = Envelope::from_bytes(&call.chain).map_err(|e| unreadable(&e))?;
    let last = env.bodies.last().ok_or_else(|| unreadable(&"no bodies"))?;
    let Body::Invocation(inv) = decode_body::<C::Base>(last)
        .map_err(|e| unreadable(&e))?
        .body
    else {
        return Err(unreadable(&"the last body is not an invocation body"));
    };
    if inv.tool.as_str() != call.name {
        return Err(McpReject::ToolMismatch);
    }
    if inv.action.as_str() != ACTION {
        return Err(McpReject::ActionNotCall);
    }
    let bound = inv.params.canonical_bytes().map_err(|e| unreadable(&e))?;
    if bound != call.canonical_arguments {
        return Err(McpReject::ArgumentsMismatch);
    }
    Ok(())
}

/// Steps 1–3: parses `request` strictly, requires a `tools/call` request
/// carrying a chain, decodes the chain strictly, and maps the arguments.
pub fn read_tools_call(request: &[u8]) -> Result<ToolsCall, McpReject> {
    let Json::Obj(mut top) = parse(request)? else {
        return Err(Malformed::Shape("the request is not an object").into());
    };
    match take(&mut top, "jsonrpc") {
        Some(Json::Str(s)) if s == "2.0" => {}
        _ => return Err(Malformed::Shape("jsonrpc is not \"2.0\"").into()),
    }
    match take(&mut top, "id") {
        Some(Json::Str(_) | Json::Int(_)) => {}
        _ => return Err(Malformed::Shape("id is not a string or an integer").into()),
    }
    match take(&mut top, "method") {
        Some(Json::Str(s)) if s == "tools/call" => {}
        Some(Json::Str(_)) => return Err(McpReject::NotToolsCall),
        _ => return Err(Malformed::Shape("method is not a string").into()),
    }
    let Some(Json::Obj(mut params)) = take(&mut top, "params") else {
        return Err(Malformed::Shape("params is not an object").into());
    };
    let Some(Json::Str(name)) = take(&mut params, "name") else {
        return Err(Malformed::Shape("params.name is not a string").into());
    };
    let arguments = match take(&mut params, "arguments") {
        None => Json::Obj(vec![]),
        Some(a @ Json::Obj(_)) => a,
        Some(_) => return Err(Malformed::Shape("params.arguments is not an object").into()),
    };
    let mut meta = match take(&mut params, "_meta") {
        None => return Err(McpReject::MissingChain),
        Some(Json::Obj(m)) => m,
        Some(_) => return Err(Malformed::Shape("params._meta is not an object").into()),
    };
    let encoded = match take(&mut meta, META_KEY) {
        None => return Err(McpReject::MissingChain),
        Some(Json::Str(s)) => s,
        Some(_) => return Err(Malformed::Shape("the chain is not a string").into()),
    };
    let chain = decode_base64url(&encoded).map_err(McpReject::ChainEncoding)?;
    let arguments = to_value(arguments)?;
    let canonical_arguments =
        encode(&arguments).map_err(|_| Malformed::Shape("the arguments do not encode"))?;
    if canonical_arguments.len() > MAX_BODY_SIZE {
        return Err(Malformed::ArgumentsTooLarge {
            len: canonical_arguments.len(),
        }
        .into());
    }
    Ok(ToolsCall {
        name,
        arguments,
        canonical_arguments,
        chain,
    })
}

/// Removes and returns the member `k` of an object (keys are distinct).
fn take(obj: &mut Vec<(String, Json)>, k: &str) -> Option<Json> {
    let i = obj.iter().position(|(x, _)| x == k)?;
    Some(obj.swap_remove(i).1)
}

/// The arguments mapping: objects to maps with text keys, arrays to arrays,
/// integers, strings, `true`, `false` and `null` to themselves. Every check
/// on the values was made when they were parsed.
fn to_value(j: Json) -> Result<Value, Malformed> {
    Ok(match j {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(b),
        Json::Int(n) => Value::Int(n),
        Json::Str(s) => Value::Text(s),
        Json::Arr(a) => Value::Array(a.into_iter().map(to_value).collect::<Result<_, _>>()?),
        Json::Obj(m) => Value::map(
            m.into_iter()
                .map(|(k, v)| Ok((Key::Text(k), to_value(v)?)))
                .collect::<Result<Vec<_>, Malformed>>()?,
        )
        .map_err(|_| Malformed::Shape("an object with two equal keys"))?,
    })
}

/// Unpadded base64url (RFC 4648 §5), as [`decode_base64url`] accepts it.
pub fn encode_base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out
}

/// Strict unpadded base64url: only the URL-safe alphabet, with no padding,
/// whitespace or other characters (checked in that order, character by
/// character), then a length that is not 1 modulo 4, and the unused low bits
/// of the last character zero, so that every byte string has exactly one
/// encoding.
pub fn decode_base64url(s: &str) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => return Err("padding"),
            b' ' | b'\t' | b'\n' | b'\r' => return Err("whitespace"),
            _ => return Err("a character outside the base64url alphabet"),
        };
        acc = acc << 6 | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Six bits left over: a length of 1 modulo 4, which encodes no byte.
    if bits == 6 {
        return Err("a length of 1 modulo 4");
    }
    if acc != 0 {
        return Err("non-zero trailing bits");
    }
    Ok(out)
}

/// A parsed JSON value, within the binding's rules.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Json {
    Null,
    Bool(bool),
    Int(i128),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

/// Parses a whole request: one JSON value, with only whitespace around it.
fn parse(request: &[u8]) -> Result<Json, Malformed> {
    if request.len() > MAX_REQUEST_SIZE {
        return Err(Malformed::TooLarge { len: request.len() });
    }
    let text = std::str::from_utf8(request).map_err(|e| Malformed::InvalidUnicode {
        at: e.valid_up_to(),
    })?;
    let mut p = Parser { text, pos: 0 };
    let v = p.value(0)?;
    p.ws();
    if p.pos != text.len() {
        return Err(p.syntax("characters after the value"));
    }
    Ok(v)
}

struct Parser<'a> {
    text: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }

    fn syntax(&self, what: &'static str) -> Malformed {
        Malformed::Syntax { at: self.pos, what }
    }

    /// RFC 8259 whitespace: space, tab, line feed and carriage return.
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    /// A value inside a container at `depth` (0 for the request itself).
    fn value(&mut self, depth: usize) -> Result<Json, Malformed> {
        self.ws();
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.syntax("an unexpected character")),
            None => Err(self.syntax("an unexpected end")),
        }
    }

    fn literal(&mut self, word: &str, v: Json) -> Result<Json, Malformed> {
        if !self.text[self.pos..].starts_with(word) {
            return Err(self.syntax("an unexpected character"));
        }
        self.pos += word.len();
        Ok(v)
    }

    fn enter(&mut self, depth: usize) -> Result<usize, Malformed> {
        let start = self.pos;
        if depth > MAX_REQUEST_DEPTH {
            return Err(Malformed::TooDeep { at: start });
        }
        self.pos += 1;
        self.ws();
        Ok(start)
    }

    fn object(&mut self, depth: usize) -> Result<Json, Malformed> {
        let start = self.enter(depth)?;
        let mut members = vec![];
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(members));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(self.syntax("expected a key"));
            }
            let k = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(self.syntax("expected ':'"));
            }
            self.pos += 1;
            members.push((k, self.value(depth)?));
            self.ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(self.syntax("expected ',' or '}'")),
            }
        }
        let mut keys: Vec<&str> = members.iter().map(|(k, _)| k.as_str()).collect();
        keys.sort_unstable();
        if keys.windows(2).any(|w| w[0] == w[1]) {
            return Err(Malformed::DuplicateKey { at: start });
        }
        Ok(Json::Obj(members))
    }

    fn array(&mut self, depth: usize) -> Result<Json, Malformed> {
        self.enter(depth)?;
        let mut items = vec![];
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value(depth)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(self.syntax("expected ',' or ']'")),
            }
        }
    }

    /// A string, unescaped, which must be NFC.
    fn string(&mut self) -> Result<String, Malformed> {
        let start = self.pos;
        self.pos += 1;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(self.syntax("an unterminated string")),
                Some(b'"') => {
                    self.pos += 1;
                    break;
                }
                Some(b'\\') => {
                    let c = match self.text.as_bytes().get(self.pos + 1) {
                        Some(b'u') => self.escaped_char()?,
                        Some(e) => {
                            let c = match e {
                                b'"' => '"',
                                b'\\' => '\\',
                                b'/' => '/',
                                b'b' => '\u{8}',
                                b'f' => '\u{c}',
                                b'n' => '\n',
                                b'r' => '\r',
                                b't' => '\t',
                                _ => return Err(self.syntax("an invalid escape")),
                            };
                            self.pos += 2;
                            c
                        }
                        None => return Err(self.syntax("an unterminated string")),
                    };
                    out.push(c);
                }
                Some(0x00..=0x1f) => return Err(self.syntax("an unescaped control character")),
                Some(_) => {
                    // A run of plain characters. Its ends are ASCII, so they
                    // fall on character boundaries.
                    let run = self.pos;
                    while matches!(self.peek(), Some(c) if c != b'"' && c != b'\\' && c >= 0x20) {
                        self.pos += 1;
                    }
                    out.push_str(&self.text[run..self.pos]);
                }
            }
        }
        if !is_nfc_str(&out) {
            return Err(Malformed::NotNfc { at: start });
        }
        Ok(out)
    }

    /// One `\uXXXX` escape, or two forming a surrogate pair, at `self.pos`.
    fn escaped_char(&mut self) -> Result<char, Malformed> {
        let at = self.pos;
        let hi = self.hex4()?;
        let cp = match hi {
            0xD800..=0xDBFF => {
                if !self.text[self.pos..].starts_with("\\u") {
                    return Err(Malformed::InvalidUnicode { at });
                }
                let lo = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&lo) {
                    return Err(Malformed::InvalidUnicode { at });
                }
                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(Malformed::InvalidUnicode { at }),
            _ => hi,
        };
        char::from_u32(cp).ok_or(Malformed::InvalidUnicode { at })
    }

    /// `\u` and four hexadecimal digits, either case.
    fn hex4(&mut self) -> Result<u32, Malformed> {
        let digits = self
            .text
            .get(self.pos + 2..self.pos + 6)
            .filter(|_| self.text[self.pos..].starts_with("\\u"))
            .ok_or(self.syntax("an invalid \\u escape"))?;
        if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(self.syntax("an invalid \\u escape"));
        }
        let v =
            u32::from_str_radix(digits, 16).map_err(|_| self.syntax("an invalid \\u escape"))?;
        self.pos += 6;
        Ok(v)
    }

    /// An integer literal (D3): no fraction, no exponent, not `-0`, within
    /// [−2⁶⁴, 2⁶⁴ − 1]. Other RFC 8259 numbers are malformed here.
    fn number(&mut self) -> Result<Json, Malformed> {
        let start = self.pos;
        let neg = self.peek() == Some(b'-');
        if neg {
            self.pos += 1;
        }
        let digits = self.pos;
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.syntax("a number without digits")),
        }
        if matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(self.syntax("a leading zero"));
        }
        let number = Malformed::Number { at: start };
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(number);
        }
        let digits = &self.text[digits..self.pos];
        if neg && digits == "0" {
            return Err(number);
        }
        let magnitude = digits.bytes().try_fold(0i128, |n, d| {
            n.checked_mul(10)?.checked_add(i128::from(d - b'0'))
        });
        let n = match (magnitude, neg) {
            (Some(m), false) => m,
            (Some(m), true) => -m,
            (None, _) => return Err(number),
        };
        if !(INT_MIN..=INT_MAX).contains(&n) {
            return Err(number);
        }
        Ok(Json::Int(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_round_trips_every_length() {
        for len in 0..64 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let s = encode_base64url(&bytes);
            assert!(!s.contains('='));
            assert_eq!(decode_base64url(&s).unwrap(), bytes, "length {len}");
        }
        // RFC 4648 §10, unpadded.
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode_base64url(plain.as_bytes()), enc);
        }
        assert_eq!(encode_base64url(&[0xfb, 0xff]), "-_8");
        for (bad, why) in [
            ("Zg==", "padding"),
            ("Zm9vYg=", "padding"),
            ("Zm9v Yg", "whitespace"),
            ("Zm9v\nYg", "whitespace"),
            ("Zm9v+g", "a character outside the base64url alphabet"),
            ("Zm9v/g", "a character outside the base64url alphabet"),
            ("Zm9vY", "a length of 1 modulo 4"),
            ("Zh", "non-zero trailing bits"),
            ("Zm9", "non-zero trailing bits"),
        ] {
            assert_eq!(decode_base64url(bad), Err(why), "{bad:?}");
        }
    }

    #[test]
    fn request_size_bound() {
        // ceil(1,116,624 × 4 / 3) + 6 × 65,536 + 65,536.
        assert_eq!(ENVELOPE_LIMITS.max_size, 1_116_624);
        assert_eq!(MAX_REQUEST_SIZE, 1_947_584);
    }

    #[test]
    fn json_escapes() {
        let j = parse(br#"["\"\\\/\b\f\n\r\t", "\u00E9\u00e9", "\ud83d\ude00"]"#).unwrap();
        assert_eq!(
            j,
            Json::Arr(vec![
                Json::Str("\"\\/\u{8}\u{c}\n\r\t".into()),
                Json::Str("éé".into()),
                Json::Str("😀".into()),
            ])
        );
        for bad in [
            r#""\x""#,
            r#""\u12""#,
            r#""\u12g4""#,
            "\"\u{1}\"",
            r#""abc"#,
        ] {
            assert!(
                matches!(parse(bad.as_bytes()), Err(Malformed::Syntax { .. })),
                "{bad}"
            );
        }
        for bad in [r#""\ud83d""#, r#""\ude00""#, r#""\ud83dA""#, r#""\ud83dx""#] {
            assert!(
                matches!(parse(bad.as_bytes()), Err(Malformed::InvalidUnicode { .. })),
                "{bad}"
            );
        }
        assert!(matches!(
            parse(b"\"\xff\""),
            Err(Malformed::InvalidUnicode { at: 1 })
        ));
    }

    #[test]
    fn json_grammar() {
        for good in [
            "{}",
            "[]",
            " {\"a\" : [1, -2, true, false, null, \"x\", {}]} \n",
        ] {
            assert!(parse(good.as_bytes()).is_ok(), "{good}");
        }
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "{a:1}",
            "01",
            "-",
            "+1",
            "1 2",
            "tru",
            "nul",
            "\u{feff}{}",
            "[1}",
            "{\"a\" 1}",
            "'a'",
        ] {
            assert!(
                matches!(parse(bad.as_bytes()), Err(Malformed::Syntax { .. })),
                "{bad:?}"
            );
        }
    }
}
