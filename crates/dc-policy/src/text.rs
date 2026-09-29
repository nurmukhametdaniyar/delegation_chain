//! The text syntax of paper §6.1, with the lexical details of D-17: whitespace
//! is insignificant, strings are double-quoted with JSON escapes and are
//! NFC-normalized, integers are decimal within the CBOR range, and booleans
//! are `true`/`false`. Keywords are contextual, so a parameter may be called
//! `in` or `approval`.

use std::collections::BTreeSet;
use std::fmt::{self, Write as _};

use dc_cbor::{INT_MAX, INT_MIN};
use dc_types::{Identifier, Principal};
use unicode_normalization::UnicodeNormalization;

use crate::ast::{Atom, Declaration, Literal, Op, Operand, Rule, Scope, ScopeForm, Type};
use crate::error::PolicyError;

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Word(String),
    Int(i128),
    Str(String),
    Sym(&'static str),
    Eof,
}

fn syntax<T>(pos: usize, msg: impl Into<String>) -> Result<T, PolicyError> {
    Err(PolicyError::Syntax {
        pos,
        msg: msg.into(),
    })
}

const SYMS: [&str; 15] = [
    "<=", ">=", "==", "<", ">", "=", ":", ",", "{", "}", "[", "]", "(", ")", ".",
];

fn lex(src: &str) -> Result<Vec<(usize, Tok)>, PolicyError> {
    let b = src.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c.is_ascii_alphabetic() {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'-') {
                i += 1;
            }
            out.push((start, Tok::Word(src[start..i].to_owned())));
        } else if c.is_ascii_digit() || (c == b'-' && b.get(i + 1).is_some_and(u8::is_ascii_digit))
        {
            let start = i;
            i += 1;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            let n: i128 = match src[start..i].parse() {
                Ok(n) if (INT_MIN..=INT_MAX).contains(&n) => n,
                _ => return syntax(start, "integer outside the CBOR range [-2^64, 2^64-1]"),
            };
            out.push((start, Tok::Int(n)));
        } else if c == b'"' {
            let (s, next) = string(src, i)?;
            out.push((i, Tok::Str(s)));
            i = next;
        } else if let Some(sym) = SYMS.iter().find(|s| src[i..].starts_with(**s)) {
            out.push((i, Tok::Sym(sym)));
            i += sym.len();
        } else {
            return syntax(
                i,
                format!(
                    "unexpected character {:?}",
                    src[i..].chars().next().unwrap()
                ),
            );
        }
    }
    out.push((src.len(), Tok::Eof));
    Ok(out)
}

/// A JSON string literal starting at `start` (the opening quote). Returns the
/// NFC-normalized content and the index after the closing quote.
fn string(src: &str, start: usize) -> Result<(String, usize), PolicyError> {
    let mut out = String::new();
    let mut chars = src[start + 1..]
        .char_indices()
        .map(|(k, c)| (start + 1 + k, c));
    let hex4 =
        |chars: &mut dyn Iterator<Item = (usize, char)>, at: usize| -> Result<u32, PolicyError> {
            let mut v = 0u32;
            for _ in 0..4 {
                match chars.next() {
                    Some((_, h)) if h.is_ascii_hexdigit() => v = v * 16 + h.to_digit(16).unwrap(),
                    _ => return syntax(at, "bad \\u escape"),
                }
            }
            Ok(v)
        };
    while let Some((k, c)) = chars.next() {
        match c {
            '"' => return Ok((out.nfc().collect(), k + 1)),
            '\\' => match chars.next() {
                Some((_, '"')) => out.push('"'),
                Some((_, '\\')) => out.push('\\'),
                Some((_, '/')) => out.push('/'),
                Some((_, 'b')) => out.push('\u{8}'),
                Some((_, 'f')) => out.push('\u{c}'),
                Some((_, 'n')) => out.push('\n'),
                Some((_, 'r')) => out.push('\r'),
                Some((_, 't')) => out.push('\t'),
                Some((_, 'u')) => {
                    let hi = hex4(&mut chars, k)?;
                    let cp = if (0xd800..0xdc00).contains(&hi) {
                        match (chars.next(), chars.next()) {
                            (Some((_, '\\')), Some((_, 'u'))) => {
                                let lo = hex4(&mut chars, k)?;
                                if !(0xdc00..0xe000).contains(&lo) {
                                    return syntax(k, "unpaired surrogate");
                                }
                                0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                            }
                            _ => return syntax(k, "unpaired surrogate"),
                        }
                    } else if (0xdc00..0xe000).contains(&hi) {
                        return syntax(k, "unpaired surrogate");
                    } else {
                        hi
                    };
                    out.push(char::from_u32(cp).expect("valid scalar value"));
                }
                _ => return syntax(k, "bad escape"),
            },
            c if (c as u32) < 0x20 => return syntax(k, "unescaped control character in string"),
            c => out.push(c),
        }
    }
    syntax(start, "unterminated string")
}

struct Parser {
    toks: Vec<(usize, Tok)>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> &Tok {
        &self.toks[self.i].1
    }

    fn pos(&self) -> usize {
        self.toks[self.i].0
    }

    fn bump(&mut self) -> Tok {
        let t = self.toks[self.i].1.clone();
        if !matches!(t, Tok::Eof) {
            self.i += 1;
        }
        t
    }

    fn is_word(&self, w: &str) -> bool {
        matches!(self.peek(), Tok::Word(x) if x == w)
    }

    fn is_sym(&self, s: &str) -> bool {
        matches!(self.peek(), Tok::Sym(x) if *x == s)
    }

    fn expect_word(&mut self, w: &str) -> Result<(), PolicyError> {
        if self.is_word(w) {
            self.bump();
            Ok(())
        } else {
            syntax(self.pos(), format!("expected `{w}`"))
        }
    }

    fn expect_sym(&mut self, s: &str) -> Result<(), PolicyError> {
        if self.is_sym(s) {
            self.bump();
            Ok(())
        } else {
            syntax(self.pos(), format!("expected `{s}`"))
        }
    }

    fn word(&mut self) -> Result<String, PolicyError> {
        match self.bump() {
            Tok::Word(w) => Ok(w),
            _ => syntax(
                self.toks[self.i.saturating_sub(1)].0,
                "expected an identifier",
            ),
        }
    }

    fn scope(&mut self) -> Result<ScopeForm, PolicyError> {
        let special = |p: &Parser, w: &str| {
            p.is_word(w) && matches!(&p.toks[p.i + 1].1, Tok::Word(x) if x == "all")
        };
        let form = if special(self, "allow") {
            self.i += 2;
            ScopeForm::AllowAll
        } else if special(self, "deny") {
            self.i += 2;
            ScopeForm::DenyAll
        } else {
            let mut rules = vec![];
            while !matches!(self.peek(), Tok::Eof) {
                rules.push(self.rule()?);
            }
            if rules.is_empty() {
                return syntax(self.pos(), "empty scope");
            }
            ScopeForm::Rules(rules)
        };
        if !matches!(self.peek(), Tok::Eof) {
            return syntax(self.pos(), "unexpected input after the scope");
        }
        Ok(form)
    }

    fn principal(&mut self) -> Result<Principal, PolicyError> {
        let pos = self.pos();
        let a = self.word()?;
        self.expect_sym(":")?;
        let b = self.word()?;
        self.expect_sym(":")?;
        let c = self.word()?;
        Principal::parse(&format!("{a}:{b}:{c}")).or_else(|e| syntax(pos, e.to_string()))
    }

    fn identifier(&mut self) -> Result<Identifier, PolicyError> {
        let pos = self.pos();
        Identifier::new(self.word()?).or_else(|e| syntax(pos, e.to_string()))
    }

    fn path(&mut self) -> Result<String, PolicyError> {
        let mut p = self.word()?;
        while self.is_sym(".") {
            self.bump();
            p.push('.');
            p.push_str(&self.word()?);
        }
        Ok(p)
    }

    fn rule(&mut self) -> Result<Rule, PolicyError> {
        self.expect_word("allow")?;
        self.expect_word("at")?;
        self.expect_sym("=")?;
        let at = self.principal()?;
        self.expect_word("tool")?;
        self.expect_sym("=")?;
        let tool = self.identifier()?;
        self.expect_word("action")?;
        self.expect_sym("=")?;
        let action = self.identifier()?;

        let mut params = Declaration::new();
        if self.is_word("params") {
            self.bump();
            self.expect_sym("{")?;
            loop {
                let pos = self.pos();
                let path = self.path()?;
                self.expect_sym(":")?;
                let ty = match self.bump() {
                    Tok::Word(w) if w == "int" => Type::Int,
                    Tok::Word(w) if w == "string" => Type::String,
                    Tok::Word(w) if w == "bool" => Type::Bool,
                    _ => return syntax(pos, "expected int, string or bool"),
                };
                if params.insert(path.clone(), ty).is_some() {
                    return syntax(pos, format!("path {path:?} declared twice (paper §6.1)"));
                }
                if self.is_sym(",") {
                    self.bump();
                } else {
                    break;
                }
            }
            self.expect_sym("}")?;
        }

        let mut atoms = vec![];
        if self.is_word("where") {
            self.bump();
            self.expr(&mut atoms)?;
        }

        let mut approval = BTreeSet::new();
        if self.is_word("approval") {
            self.bump();
            self.expect_word("requires")?;
            loop {
                approval.insert(self.principal()?);
                if self.is_sym(",") {
                    self.bump();
                } else {
                    break;
                }
            }
        }
        Ok(Rule {
            at,
            tool,
            action,
            params,
            atoms,
            approval,
        })
    }

    /// `expr ::= expr "and" expr | "(" expr ")" | atom`. The clause is a
    /// conjunction, so parentheses only group; atoms keep written order.
    fn expr(&mut self, atoms: &mut Vec<Atom>) -> Result<(), PolicyError> {
        self.term(atoms)?;
        while self.is_word("and") {
            self.bump();
            self.term(atoms)?;
        }
        Ok(())
    }

    fn term(&mut self, atoms: &mut Vec<Atom>) -> Result<(), PolicyError> {
        if self.is_sym("(") {
            self.bump();
            self.expr(atoms)?;
            self.expect_sym(")")
        } else {
            atoms.push(self.atom()?);
            Ok(())
        }
    }

    fn atom(&mut self) -> Result<Atom, PolicyError> {
        let path = self.path()?;
        let pos = self.pos();
        let op = match self.bump() {
            Tok::Sym("<") => Op::Lt,
            Tok::Sym("<=") => Op::Le,
            Tok::Sym("==") => Op::Eq,
            Tok::Sym(">=") => Op::Ge,
            Tok::Sym(">") => Op::Gt,
            Tok::Word(w) => match w.as_str() {
                "starts_with" => Op::StartsWith,
                "ends_with" => Op::EndsWith,
                "contains" => Op::Contains,
                "in" => Op::In,
                "under" => Op::Under,
                _ => return syntax(pos, "expected an operator"),
            },
            _ => return syntax(pos, "expected an operator"),
        };
        let pos = self.pos();
        let operand = match op {
            Op::In => {
                self.expect_sym("[")?;
                let mut items = vec![self.value()?];
                while self.is_sym(",") {
                    self.bump();
                    items.push(self.value()?);
                }
                self.expect_sym("]")?;
                Operand::List(items)
            }
            // `path strop string-value` and `path "under" string-value`.
            Op::StartsWith | Op::EndsWith | Op::Contains | Op::Under => match self.bump() {
                Tok::Str(s) => Operand::One(Literal::Str(s)),
                _ => return syntax(pos, "expected a string"),
            },
            _ => Operand::One(self.value()?),
        };
        Ok(Atom { op, path, operand })
    }

    fn value(&mut self) -> Result<Literal, PolicyError> {
        let pos = self.pos();
        match self.bump() {
            Tok::Int(n) => Ok(Literal::Int(n)),
            Tok::Str(s) => Ok(Literal::Str(s)),
            Tok::Word(w) if w == "true" => Ok(Literal::Bool(true)),
            Tok::Word(w) if w == "false" => Ok(Literal::Bool(false)),
            _ => syntax(pos, "expected an integer, string or boolean"),
        }
    }
}

impl Scope {
    /// Parses and validates the text form. A grammar error is
    /// `PolicyError::Syntax`; a well-formedness error is `Malformed`.
    pub fn parse(src: &str) -> Result<Scope, PolicyError> {
        let mut p = Parser {
            toks: lex(src)?,
            i: 0,
        };
        Scope::new(p.scope()?)
    }

    /// Parses without validating: for tests of the validator and of the
    /// P-15 regression.
    #[cfg(feature = "test-hooks")]
    pub fn parse_unchecked(src: &str) -> Result<Scope, PolicyError> {
        let mut p = Parser {
            toks: lex(src)?,
            i: 0,
        };
        Ok(Scope::new_unchecked(p.scope()?))
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_literal(out: &mut String, l: &Literal) {
    match l {
        Literal::Int(n) => {
            let _ = write!(out, "{n}");
        }
        Literal::Str(s) => write_string(out, s),
        Literal::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
    }
}

/// The text form, one rule per line. `Scope::parse` of the output gives the
/// scope back.
impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rules = match self.form() {
            ScopeForm::AllowAll => return f.write_str("allow all"),
            ScopeForm::DenyAll => return f.write_str("deny all"),
            ScopeForm::Rules(r) => r,
        };
        let mut out = String::new();
        for (i, r) in rules.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            let _ = write!(out, "allow at={} tool={} action={}", r.at, r.tool, r.action);
            if !r.params.is_empty() {
                out.push_str(" params { ");
                let decl: Vec<String> = r.params.iter().map(|(p, t)| format!("{p}: {t}")).collect();
                out.push_str(&decl.join(", "));
                out.push_str(" }");
            }
            for (k, a) in r.atoms.iter().enumerate() {
                out.push_str(if k == 0 { " where " } else { " and " });
                let _ = write!(out, "{} {} ", a.path, a.op.text());
                match &a.operand {
                    Operand::One(l) => write_literal(&mut out, l),
                    Operand::List(l) => {
                        out.push('[');
                        for (j, x) in l.iter().enumerate() {
                            if j > 0 {
                                out.push_str(", ");
                            }
                            write_literal(&mut out, x);
                        }
                        out.push(']');
                    }
                }
            }
            if !r.approval.is_empty() {
                let names: Vec<&str> = r.approval.iter().map(Principal::as_str).collect();
                let _ = write!(out, " approval requires {}", names.join(", "));
            }
        }
        f.write_str(&out)
    }
}
