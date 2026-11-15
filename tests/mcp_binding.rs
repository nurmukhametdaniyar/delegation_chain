//! The MCP binding (SPEC §10.6, §11.5; D-104): a `tools/call` request
//! against the chain it carries, before and through Verify.

mod common;

use common::*;
use dc_cbor::{INT_MAX, INT_MIN, Key, Value};
use dc_policy::{Decision, Scope};
use dc_types::Params;
use dc_verifier::Reject;
use dc_verifier::mcp::{
    MAX_REQUEST_SIZE, META_KEY, Malformed, McpReject, encode_base64url, read_tools_call,
};

/// The paper's §6.2 policy, rule 1, with the action MCP binds (D2); a tool
/// that takes any integer and string; a tool without parameters.
const MCP_POLICY: &str = r#"allow at=orgb:service:payments
  tool=payments action=call
  params { amount: int,
           to_account: string }
  where amount <= 1000
allow at=orgb:service:payments
  tool=echo action=call
  params { n: int, s: string }
allow at=orgb:service:payments
  tool=ping action=call"#;

/// SPEC §10.6's worked example; `CHAIN` stands for the chain.
const WORKED_EXAMPLE: &str = r#"{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "payments",
    "arguments": {
      "amount": 500,
      "to_account": "acct_vendor_a"
    },
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientCapabilities": {},
      "io.github.nurmukhametdaniyar/delegationchain": "CHAIN"
    }
  }
}"#;

/// Canon of the worked example's arguments, as SPEC §10.6 prints it.
const WORKED_EXAMPLE_CANON: &str =
    "a266616d6f756e741901f46a746f5f6163636f756e746d616363745f76656e646f725f61";

fn suite() -> Suite {
    let mut s = Suite::new();
    s.policy = Scope::parse(MCP_POLICY).unwrap();
    s.hash = s.w.publish(&s.policy);
    s
}

fn params(entries: Vec<(&str, Value)>) -> Params {
    Params::new(Value::map(entries.into_iter().map(|(k, v)| (Key::from(k), v))).unwrap()).unwrap()
}

/// An honest chain at N = 3 (the medium profile's length), every scope the
/// MCP policy, invoking `tool` and `action` with `p` at payments.
fn chain(s: &mut Suite, tool: &str, action: &str, p: Params) -> Vec<u8> {
    let scopes = vec![s.policy.clone(); 3];
    s.chain_with(&scopes, PAYMENTS, tool, action, p).to_bytes()
}

fn medium(s: &mut Suite) -> Vec<u8> {
    chain(s, "payments", "call", transfer(500, "acct_vendor_a"))
}

fn echo(s: &mut Suite, n: i128, text: &str) -> Vec<u8> {
    chain(
        s,
        "echo",
        "call",
        params(vec![("n", Value::Int(n)), ("s", Value::text(text))]),
    )
}

/// A `tools/call` request with `meta` as `params._meta` (JSON text) and
/// `arguments` (JSON text) if given.
fn request_with(name: &str, arguments: Option<&str>, meta: &str) -> Vec<u8> {
    let arguments = arguments
        .map(|a| format!(r#""arguments":{a},"#))
        .unwrap_or_default();
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}",{arguments}"_meta":{meta}}}}}"#
    )
    .into_bytes()
}

/// A `tools/call` request carrying `encoded` under the binding's key.
fn request_encoded(name: &str, arguments: Option<&str>, encoded: &str) -> Vec<u8> {
    request_with(name, arguments, &format!(r#"{{"{META_KEY}":"{encoded}"}}"#))
}

/// A `tools/call` request carrying `chain`.
fn request(name: &str, arguments: Option<&str>, chain: &[u8]) -> Vec<u8> {
    request_encoded(name, arguments, &encode_base64url(chain))
}

fn malformed(r: Result<impl std::fmt::Debug, McpReject>) -> Malformed {
    match r {
        Err(McpReject::Malformed(m)) => m,
        other => panic!("expected a malformed request, got {other:?}"),
    }
}

#[test]
fn medium_profile_round_trip() {
    let mut s = suite();
    let v = s.verifier();
    let c = medium(&mut s);
    let req = WORKED_EXAMPLE.replace("CHAIN", &encode_base64url(&c));
    let call = read_tools_call(req.as_bytes()).unwrap();
    let hex: String = call
        .canonical_arguments
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(hex, WORKED_EXAMPLE_CANON);
    assert_eq!(call.chain, c);
    let a = v.verify_mcp_call(req.as_bytes(), s.now()).unwrap();
    assert_eq!((a.n, a.decision), (3, Decision::Allow));
}

#[test]
fn json_key_order_does_not_matter() {
    let mut s = suite();
    let v = s.verifier();
    let c = medium(&mut s);
    // Arguments, params and the request itself in another order.
    let req = format!(
        r#"{{"params":{{"_meta":{{"{META_KEY}":"{}"}},"arguments":{{"to_account":"acct_vendor_a","amount":500}},"name":"payments"}},"method":"tools/call","id":"x","jsonrpc":"2.0"}}"#,
        encode_base64url(&c)
    );
    assert!(v.verify_mcp_call(req.as_bytes(), s.now()).is_ok());
}

#[test]
fn nfc_strings_and_keys() {
    let mut s = suite();
    let v = s.verifier();
    // U+00E9, escaped and literal: accepted as a value, end to end.
    for text in [r#""\u00e9""#, "\"\u{e9}\""] {
        let c = echo(&mut s, 1, "\u{e9}");
        let req = request("echo", Some(&format!(r#"{{"n":1,"s":{text}}}"#)), &c);
        assert!(v.verify_mcp_call(&req, s.now()).is_ok(), "{text}");
    }
    // As a key, the binding accepts it; the policy cannot declare it (keys
    // are identifiers), so Verify denies it at line 40.
    for key in [r#""\u00e9""#, "\"\u{e9}\""] {
        let c = chain(
            &mut s,
            "echo",
            "call",
            params(vec![("\u{e9}", Value::Int(1))]),
        );
        let req = request("echo", Some(&format!("{{{key}:1}}")), &c);
        assert_eq!(
            v.verify_mcp_call(&req, s.now()),
            Err(McpReject::Verify(Reject::L40Denied)),
            "{key}"
        );
    }
    // e + U+0301, escaped and literal: not NFC, as a value and as a key.
    let c = echo(&mut s, 1, "\u{e9}");
    for text in [r#""e\u0301""#, "\"e\u{301}\""] {
        let as_value = request("echo", Some(&format!(r#"{{"n":1,"s":{text}}}"#)), &c);
        let as_key = request("echo", Some(&format!("{{{text}:1}}")), &c);
        for req in [as_value, as_key] {
            assert!(
                matches!(
                    malformed(v.verify_mcp_call(&req, s.now())),
                    Malformed::NotNfc { .. }
                ),
                "{text}"
            );
        }
    }
    // A lone surrogate, high or low, as a value and as a key.
    for text in [r#""\ud800""#, r#""\udc00""#, r#""a\ud800b""#] {
        let as_value = request("echo", Some(&format!(r#"{{"n":1,"s":{text}}}"#)), &c);
        let as_key = request("echo", Some(&format!("{{{text}:1}}")), &c);
        for req in [as_value, as_key] {
            assert!(
                matches!(
                    malformed(v.verify_mcp_call(&req, s.now())),
                    Malformed::InvalidUnicode { .. }
                ),
                "{text}"
            );
        }
    }
    // Only the two accepted requests consumed a nonce.
    assert_eq!(v.nonce_cache().len(), 2);
}

#[test]
fn integer_range() {
    let mut s = suite();
    let v = s.verifier();
    // 2^64 − 1 and −2^64: accepted, end to end.
    for (n, text) in [
        (INT_MAX, "18446744073709551615"),
        (INT_MIN, "-18446744073709551616"),
    ] {
        let c = echo(&mut s, n, "x");
        let req = request("echo", Some(&format!(r#"{{"n":{text},"s":"x"}}"#)), &c);
        let call = read_tools_call(&req).unwrap();
        assert_eq!(call.arguments.get(&Key::from("n")), Some(&Value::Int(n)));
        assert!(v.verify_mcp_call(&req, s.now()).is_ok(), "{text}");
    }
    // 2^64 and −2^64 − 1, and far outside.
    let c = echo(&mut s, 1, "x");
    for text in [
        "18446744073709551616",
        "-18446744073709551617",
        "340282366920938463463374607431768211456",
        "1000000000000000000000000000000000000000000000000000",
    ] {
        let req = request("echo", Some(&format!(r#"{{"n":{text},"s":"x"}}"#)), &c);
        assert!(
            matches!(
                malformed(v.verify_mcp_call(&req, s.now())),
                Malformed::Number { .. }
            ),
            "{text}"
        );
    }
}

#[test]
fn non_integer_numbers_rejected() {
    let mut s = suite();
    let v = s.verifier();
    let c = echo(&mut s, 1, "x");
    for text in [
        "1.0", "1e3", "1E3", "0.5", "-0", "-0.0", "1e-3", "1E+3", "10.00",
    ] {
        let req = request("echo", Some(&format!(r#"{{"n":{text},"s":"x"}}"#)), &c);
        assert!(
            matches!(
                malformed(v.verify_mcp_call(&req, s.now())),
                Malformed::Number { .. }
            ),
            "{text}"
        );
    }
    // Not JSON numbers at all.
    for text in ["01", "+1", ".5", "1.", "0x10"] {
        let req = request("echo", Some(&format!(r#"{{"n":{text},"s":"x"}}"#)), &c);
        assert!(v.verify_mcp_call(&req, s.now()).is_err(), "{text}");
    }
    // Zero itself is an integer literal.
    let c0 = echo(&mut s, 0, "x");
    let req = request("echo", Some(r#"{"n":0,"s":"x"}"#), &c0);
    assert!(v.verify_mcp_call(&req, s.now()).is_ok());
}

#[test]
fn duplicate_keys_rejected() {
    let mut s = suite();
    let v = s.verifier();
    let c = echo(&mut s, 1, "x");
    let enc = encode_base64url(&c);
    let requests = [
        // In the arguments, at the top and nested; equal after unescaping.
        request("echo", Some(r#"{"n":1,"s":"x","n":1}"#), &c),
        request("echo", Some(r#"{"n":1,"s":"x","\u006e":2}"#), &c),
        request("echo", Some(r#"{"n":1,"s":{"a":1,"a":1}}"#), &c),
        request("echo", Some(r#"{"n":1,"s":[{"a":[{"b":1,"b":2}]}]}"#), &c),
        // In the request around them.
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"tools/call","params":{{"name":"echo","arguments":{{"n":1,"s":"x"}},"_meta":{{"{META_KEY}":"{enc}"}}}}}}"#
        )
        .into_bytes(),
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"ping","name":"echo","arguments":{{"n":1,"s":"x"}},"_meta":{{"{META_KEY}":"{enc}"}}}}}}"#
        )
        .into_bytes(),
        request_with(
            "echo",
            Some(r#"{"n":1,"s":"x"}"#),
            &format!(r#"{{"{META_KEY}":"{enc}","{META_KEY}":"{enc}"}}"#),
        ),
    ];
    for req in requests {
        assert!(
            matches!(
                malformed(v.verify_mcp_call(&req, s.now())),
                Malformed::DuplicateKey { .. }
            ),
            "{}",
            String::from_utf8_lossy(&req)
        );
    }
    // The same chain, with the arguments it binds, is accepted.
    let req = request("echo", Some(r#"{"n":1,"s":"x"}"#), &c);
    assert!(v.verify_mcp_call(&req, s.now()).is_ok());
}

/// `{"a":{"a":…{"a":1}…}}`, `levels` objects deep, and its parameter map.
fn nested(levels: usize) -> (String, Value) {
    let mut json = "1".to_string();
    let mut value = Value::Int(1);
    for _ in 0..levels {
        json = format!(r#"{{"a":{json}}}"#);
        value = Value::map(vec![(Key::from("a"), value)]).unwrap();
    }
    (json, value)
}

/// Depth is counted as D-02 counts it in B_N, where the arguments are the
/// parameter map at depth 2: 15 levels of arguments reach depth 16, the
/// most a body holds; 16 levels reach 17.
#[test]
fn depth_16_accepted_17_rejected() {
    let mut s = suite();
    let v = s.verifier();
    // Depth 16: the binding accepts it. No rule declares a 15-segment path
    // (paths have at most 8), so Verify denies it at line 40.
    let (json, value) = nested(15);
    let c = chain(&mut s, "echo", "call", Params::new(value).unwrap());
    let req = request("echo", Some(&json), &c);
    assert_eq!(
        v.verify_mcp_call(&req, s.now()),
        Err(McpReject::Verify(Reject::L40Denied))
    );
    // Depth 17: malformed, before the chain is read.
    let (json, value) = nested(16);
    let req = request("echo", Some(&json), &c);
    assert!(matches!(
        malformed(v.verify_mcp_call(&req, s.now())),
        Malformed::TooDeep { .. }
    ));
    // Why: no body can carry it. A map holding it as its key-7 entry, as an
    // invocation body holds its parameters, does not encode (D-02); at 15
    // levels it does.
    let in_body = |v: Value| dc_cbor::encode(&Value::map(vec![(Key::Uint(7), v)]).unwrap());
    assert!(in_body(value).is_err());
    assert!(in_body(nested(15).1).is_ok());
    // Arrays count as objects do.
    let deep_array = format!(r#"{{"n":1,"s":{}}}"#, "[".repeat(15) + &"]".repeat(15));
    let req = request("echo", Some(&deep_array), &c);
    assert!(matches!(
        malformed(v.verify_mcp_call(&req, s.now())),
        Malformed::TooDeep { .. }
    ));
}

/// An echo chain whose base64url length is not a multiple of 4, so that it
/// has padding and unused trailing bits to tamper with.
fn chain_with_trailing_bits(s: &mut Suite) -> (Vec<u8>, String) {
    for text in ["a", "ab", "abc"] {
        let c = echo(s, 1, text);
        let enc = encode_base64url(&c);
        if !enc.len().is_multiple_of(4) {
            return (c, format!(r#"{{"n":1,"s":"{text}"}}"#));
        }
    }
    unreachable!("three consecutive lengths cover every residue modulo 3")
}

#[test]
fn chain_encoding_strict() {
    let mut s = suite();
    let v = s.verifier();
    let (c, args) = chain_with_trailing_bits(&mut s);
    let enc = encode_base64url(&c);
    let args = Some(args.as_str());
    let t = s.now();
    let reject = |req: Vec<u8>| v.verify_mcp_call(&req, t);

    // The key missing: from `_meta`, and `_meta` itself.
    assert_eq!(
        reject(request_with("echo", args, r#"{"other":"x"}"#)),
        Err(McpReject::MissingChain)
    );
    assert_eq!(
        reject(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"n":1,"s":"a"}}}"#
                .to_string()
                .into_bytes()
        ),
        Err(McpReject::MissingChain)
    );
    // Padded.
    let padded = format!("{enc}{}", "=".repeat(4 - enc.len() % 4));
    assert_eq!(
        reject(request_encoded("echo", args, &padded)),
        Err(McpReject::ChainEncoding("padding"))
    );
    // Whitespace: a space, and an escaped line feed, inside.
    let mid = enc.len() / 2;
    for ws in [" ", "\\n"] {
        let spaced = format!("{}{ws}{}", &enc[..mid], &enc[mid..]);
        assert_eq!(
            reject(request_encoded("echo", args, &spaced)),
            Err(McpReject::ChainEncoding("whitespace")),
            "{ws}"
        );
    }
    // Non-canonical trailing bits: the last character's lowest bit, unused
    // whether 2 or 4 bits are left over.
    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let last = ALPHABET.find(enc.chars().last().unwrap()).unwrap();
    let tampered = format!(
        "{}{}",
        &enc[..enc.len() - 1],
        &ALPHABET[(last ^ 1)..=(last ^ 1)]
    );
    assert_eq!(
        reject(request_encoded("echo", args, &tampered)),
        Err(McpReject::ChainEncoding("non-zero trailing bits"))
    );
    // The standard alphabet's characters.
    let standard = enc.replace('-', "+").replace('_', "/");
    if standard != enc {
        assert!(matches!(
            reject(request_encoded("echo", args, &standard)),
            Err(McpReject::ChainEncoding(_))
        ));
    }
    // Not a string.
    assert!(matches!(
        malformed(reject(request_with(
            "echo",
            args,
            &format!(r#"{{"{META_KEY}":1}}"#)
        ))),
        Malformed::Shape(_)
    ));
    // None of these consumed the nonce: the chain, correctly encoded, is
    // accepted.
    assert!(reject(request_encoded("echo", args, &enc)).is_ok());
}

#[test]
fn method_other_than_tools_call_rejected() {
    let mut s = suite();
    let v = s.verifier();
    let c = medium(&mut s);
    let ok = String::from_utf8(request(
        "payments",
        Some(r#"{"amount":500,"to_account":"acct_vendor_a"}"#),
        &c,
    ))
    .unwrap();
    for method in ["tools/list", "tools/Call", "resources/read", ""] {
        let req = ok.replace(
            r#""method":"tools/call""#,
            &format!(r#""method":"{method}""#),
        );
        assert_eq!(
            v.verify_mcp_call(req.as_bytes(), s.now()),
            Err(McpReject::NotToolsCall),
            "{method}"
        );
    }
    assert!(v.verify_mcp_call(ok.as_bytes(), s.now()).is_ok());
}

#[test]
fn tool_and_action_bound() {
    let mut s = suite();
    let v = s.verifier();
    let args = Some(r#"{"amount":500,"to_account":"acct_vendor_a"}"#);
    // params.name is not B_N's tool.
    let c = medium(&mut s);
    for name in ["files", "Payments", "payments ", "payment"] {
        assert_eq!(
            v.verify_mcp_call(&request(name, args, &c), s.now()),
            Err(McpReject::ToolMismatch),
            "{name}"
        );
    }
    // B_N's action is not `call`: the paper's medium-profile invocation as
    // it stands, whose action is `transfer`.
    let transfer_chain = chain(
        &mut s,
        "payments",
        "transfer",
        transfer(500, "acct_vendor_a"),
    );
    assert_eq!(
        v.verify_mcp_call(&request("payments", args, &transfer_chain), s.now()),
        Err(McpReject::ActionNotCall)
    );
    assert!(
        v.verify_mcp_call(&request("payments", args, &c), s.now())
            .is_ok()
    );
}

#[test]
fn arguments_bound_before_verify() {
    let mut s = suite();
    let v = s.verifier();
    let c = medium(&mut s);
    let wrong = [
        // Extra.
        r#"{"amount":500,"to_account":"acct_vendor_a","memo":"x"}"#,
        // Missing.
        r#"{"amount":500}"#,
        r#"{}"#,
        // Changed: value, type, key.
        r#"{"amount":501,"to_account":"acct_vendor_a"}"#,
        r#"{"amount":500,"to_account":"acct_vendor_b"}"#,
        r#"{"amount":"500","to_account":"acct_vendor_a"}"#,
        r#"{"amount":500,"to_account":["acct_vendor_a"]}"#,
        r#"{"amount":500,"to_acount":"acct_vendor_a"}"#,
    ];
    for args in wrong {
        let (r, ops) = v.verify_mcp_call_counted(&request("payments", Some(args), &c), s.now());
        assert_eq!(r, Err(McpReject::ArgumentsMismatch), "{args}");
        // Rejected before Verify: no signature check, no pairing, no
        // resolution, no policy work.
        assert_eq!(ops.sig_verifications, 0, "{args}");
        assert_eq!(ops.pairings(), 0, "{args}");
        assert_eq!(ops.resolver_calls, 0, "{args}");
        assert_eq!(ops.policy_store_calls, 0, "{args}");
        assert_eq!(ops.contains_calls, 0, "{args}");
        assert_eq!(ops.evaluate_calls, 0, "{args}");
    }
    // The same is true of every other rejection before Verify.
    let (r, ops) = v.verify_mcp_call_counted(
        &request(
            "files",
            Some(r#"{"amount":500,"to_account":"acct_vendor_a"}"#),
            &c,
        ),
        s.now(),
    );
    assert_eq!(r, Err(McpReject::ToolMismatch));
    assert_eq!((ops.sig_verifications, ops.resolver_calls), (0, 0));
    // No nonce was consumed: the same chain with its arguments is accepted.
    assert!(v.nonce_cache().is_empty());
    let req = request(
        "payments",
        Some(r#"{"amount":500,"to_account":"acct_vendor_a"}"#),
        &c,
    );
    let (r, ops) = v.verify_mcp_call_counted(&req, s.now());
    assert!(r.is_ok());
    assert!(ops.sig_verifications > 0 || ops.pairings() > 0);
    // Accepting it consumed the nonce.
    assert_eq!(v.nonce_cache().len(), 1);
    assert_eq!(
        v.verify_mcp_call(&req, s.now()),
        Err(McpReject::Verify(Reject::L17Replay))
    );
}

#[test]
fn absent_arguments_equal_empty_object() {
    let mut s = suite();
    let v = s.verifier();
    let c = chain(&mut s, "ping", "call", Params::empty());
    let absent = request("ping", None, &c);
    let empty = request("ping", Some("{}"), &c);
    assert_eq!(read_tools_call(&absent), read_tools_call(&empty));
    assert_eq!(
        read_tools_call(&absent).unwrap().canonical_arguments,
        vec![0xa0]
    );
    assert!(v.verify_mcp_call(&absent, s.now()).is_ok());
    let c2 = chain(&mut s, "ping", "call", Params::empty());
    assert!(
        v.verify_mcp_call(&request("ping", Some("{}"), &c2), s.now())
            .is_ok()
    );
    // `null` is not an absent object.
    assert!(matches!(
        malformed(v.verify_mcp_call(&request("ping", Some("null"), &c), s.now())),
        Malformed::Shape(_)
    ));
}

/// D3 and D4 hold for every number and string of the request, not only the
/// arguments; the request's size is bounded before it is parsed.
#[test]
fn rules_apply_to_the_whole_request() {
    let mut s = suite();
    let v = s.verifier();
    let c = medium(&mut s);
    let args = r#"{"amount":500,"to_account":"acct_vendor_a"}"#;
    let ok = String::from_utf8(request("payments", Some(args), &c)).unwrap();
    let t = s.now();
    let check = |req: String| malformed(v.verify_mcp_call(req.as_bytes(), t));
    assert!(matches!(
        check(ok.replace(r#""id":1"#, r#""id":1.0"#)),
        Malformed::Number { .. }
    ));
    assert!(matches!(
        check(ok.replace(r#""_meta":{"#, r#""_meta":{"progress":0.5,"#)),
        Malformed::Number { .. }
    ));
    assert!(matches!(
        check(ok.replace(r#""_meta":{"#, r#""_meta":{"note":"e\u0301","#)),
        Malformed::NotNfc { .. }
    ));
    assert!(matches!(
        check(ok.replace(r#""jsonrpc":"2.0""#, r#""jsonrpc":"1.0""#)),
        Malformed::Shape(_)
    ));
    assert!(matches!(
        check(ok.replace(r#""id":1,"#, "")),
        Malformed::Shape(_)
    ));
    assert!(matches!(
        check(ok.replace(r#""id":1"#, r#""id":null"#)),
        Malformed::Shape(_)
    ));
    assert!(matches!(
        check(format!("{ok} {{}}")),
        Malformed::Syntax { .. }
    ));
    // Larger than the bound, by whitespace alone.
    let padded = format!("{ok}{}", " ".repeat(MAX_REQUEST_SIZE + 1 - ok.len()));
    assert!(matches!(check(padded), Malformed::TooLarge { .. }));
    // Arguments whose canonical encoding passes the body limit (D-03).
    let big = format!(
        r#"{{"amount":500,"to_account":"{}"}}"#,
        "a".repeat(64 * 1024)
    );
    let req = String::from_utf8(request("payments", Some(&big), &c)).unwrap();
    assert!(matches!(check(req), Malformed::ArgumentsTooLarge { .. }));
    // Other members of the request and of `_meta` are ignored.
    let extra = ok.replace(
        r#""_meta":{"#,
        r#""inputResponses":{},"_meta":{"progressToken":7,"#,
    );
    assert!(v.verify_mcp_call(extra.as_bytes(), t).is_ok());
}
