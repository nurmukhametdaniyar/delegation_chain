//! The MCP expressiveness study's cross-check (D-105; exploratory).
//!
//! Reads JSON lines from stdin, one per tool, as `scripts/mcp_expressiveness.py
//! classify` writes them: `{"tool", "key", "scope", "calls": [{"request",
//! "expect"}]}`. Each request runs through the binding's parser
//! ([`read_tools_call`]), the policy's leaf mapping ([`flatten`]) and, when the
//! line carries a scope, [`evaluate`] at `v:service:mcp` with action `call`.
//! Prints one JSON line per call: `{"tool", "got"}`, where `got` is `allow`,
//! `approval`, `deny`, `typed` (no scope given), `untyped` (a leaf of no
//! type), `key` (a key outside the identifier grammar), `tool name`,
//! `malformed: ...` or `scope: ...` (the scope does not parse).

use std::io::{self, BufRead, BufWriter, Write};

use dc_policy::{Decision, Invocation, Leaf, Scope, evaluate, flatten};
use dc_types::{Identifier, Principal};
use dc_verifier::mcp::read_tools_call;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Line {
    tool: String,
    scope: Option<String>,
    calls: Vec<Call>,
}

#[derive(Deserialize)]
struct Call {
    request: String,
}

#[derive(Serialize)]
struct Out<'a> {
    tool: &'a str,
    got: String,
}

fn outcome(scope: Option<&Scope>, request: &str, aud: &Principal, action: &Identifier) -> String {
    let call = match read_tools_call(request.as_bytes()) {
        Ok(c) => c,
        Err(e) => return format!("malformed: {e}"),
    };
    let Ok(tool) = Identifier::new(call.name.clone()) else {
        return "tool name".into();
    };
    let Some(leaves) = flatten(&call.arguments) else {
        return "key".into();
    };
    if leaves.iter().any(|(_, l)| matches!(l, Leaf::Untyped)) {
        return "untyped".into();
    }
    let Some(scope) = scope else {
        return "typed".into();
    };
    let inv = Invocation {
        aud,
        tool: &tool,
        action,
        params: &call.arguments,
    };
    match evaluate(scope, &inv) {
        Decision::Allow => "allow".into(),
        Decision::AllowWithApproval(_) => "approval".into(),
        Decision::Deny => "deny".into(),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let aud = Principal::parse("v:service:mcp")?;
    let action = Identifier::new("call")?;
    let stdin = io::stdin();
    let mut out = BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line: Line = serde_json::from_str(&line?)?;
        let parsed = line.scope.as_deref().map(Scope::parse);
        for call in &line.calls {
            let got = match &parsed {
                Some(Err(e)) => format!("scope: {e}"),
                Some(Ok(s)) => outcome(Some(s), &call.request, &aud, &action),
                None => outcome(None, &call.request, &aud, &action),
            };
            serde_json::to_writer(
                &mut out,
                &Out {
                    tool: &line.tool,
                    got,
                },
            )?;
            out.write_all(b"\n")?;
        }
    }
    out.flush()?;
    Ok(())
}
