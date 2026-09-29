//! SPEC §9.7 fixed tests: paper examples, Remark 1, reflexivity, the
//! special forms (D-24), the P-15 regression, well-formedness (paper §6.1),
//! the parser (D-17) and evaluation (paper §6.3).

use dc_cbor::{INT_MAX, INT_MIN, Key, Value};
use dc_policy::{
    Decision, Invocation, Literal, Op, PolicyError, Scope, ScopeForm, contains,
    contains_pre_review, evaluate,
};
use dc_types::{Identifier, Principal};

/// The paper's §6.2 example, verbatim.
const PAPER_6_2: &str = r#"allow at=orgb:service:payments
  tool=payments action=transfer
  params { amount: int,
           to_account: string }
  where amount <= 1000
allow at=orgb:service:payments
  tool=payments action=transfer
  params { amount: int,
           to_account: string }
  where amount <= 100000
        and to_account in
            ["acct_vendor_a", "acct_vendor_b"]
  approval requires orga:approver:finance
allow at=orgb:service:files
  tool=files action=read
  params { file: string }
  where file under "/home/agent/workspace""#;

/// The same policy in the order paper §6.3 recommends: the approval rule
/// before the overlapping permissive one.
const RECOMMENDED_ORDER: &str = r#"
allow at=orgb:service:payments tool=payments action=transfer
  params { amount: int, to_account: string }
  where amount <= 100000 and to_account in ["acct_vendor_a", "acct_vendor_b"]
  approval requires orga:approver:finance
allow at=orgb:service:payments tool=payments action=transfer
  params { amount: int, to_account: string }
  where amount <= 1000
allow at=orgb:service:files tool=files action=read
  params { file: string } where file under "/home/agent/workspace""#;

/// A rule's CBOR map, for editing a single field in a test.
type RuleMap = Vec<(Key, Value)>;

fn p(s: &str) -> Principal {
    Principal::parse(s).unwrap()
}

fn id(s: &str) -> Identifier {
    Identifier::new(s).unwrap()
}

fn params(entries: &[(&str, Value)]) -> Value {
    Value::map(entries.iter().map(|(k, v)| (Key::from(*k), v.clone()))).unwrap()
}

fn eval(scope: &Scope, aud: &str, tool: &str, action: &str, prm: &Value) -> Decision {
    let (aud, tool, action) = (p(aud), id(tool), id(action));
    evaluate(
        scope,
        &Invocation {
            aud: &aud,
            tool: &tool,
            action: &action,
            params: prm,
        },
    )
}

fn transfer(amount: u64, to: &str) -> Value {
    params(&[
        ("amount", Value::uint(amount)),
        ("to_account", Value::text(to)),
    ])
}

fn malformed(src: &str) -> String {
    match Scope::parse(src) {
        Err(PolicyError::Malformed(m)) => m,
        other => panic!("expected malformed, got {other:?} for {src}"),
    }
}

// ---- paper examples (SPEC §9.7) ----

#[test]
fn paper_example_parses_verbatim() {
    let s = Scope::parse(PAPER_6_2).unwrap();
    let ScopeForm::Rules(rules) = s.form() else {
        panic!()
    };
    assert_eq!(rules.len(), 3);
    assert_eq!(
        rules[1].approval.iter().next().unwrap().as_str(),
        "orga:approver:finance"
    );
    assert_eq!(rules[1].atoms[1].op, Op::In);
}

#[test]
fn paper_example_decisions() {
    let s = Scope::parse(PAPER_6_2).unwrap();
    // 500 units to acct_vendor_a matches rule 1 first: allow, no approval
    // (paper §6.3, "Match order").
    assert_eq!(
        eval(
            &s,
            "orgb:service:payments",
            "payments",
            "transfer",
            &transfer(500, "acct_vendor_a")
        ),
        Decision::Allow
    );
    // 5,000 to a vendor falls through to rule 2.
    assert_eq!(
        eval(
            &s,
            "orgb:service:payments",
            "payments",
            "transfer",
            &transfer(5000, "acct_vendor_a")
        ),
        Decision::AllowWithApproval(vec![p("orga:approver:finance")])
    );
    // An undeclared override_limits parameter: closed world, deny.
    let mut extra = transfer(500, "acct_vendor_a");
    if let Value::Map(m) = &mut extra {
        m.push((Key::from("override_limits"), Value::Bool(true)));
    }
    assert_eq!(
        eval(&s, "orgb:service:payments", "payments", "transfer", &extra),
        Decision::Deny
    );
    // A path escaping the workspace through /../.
    let escape = params(&[(
        "file",
        Value::text("/home/agent/workspace/../../etc/passwd"),
    )]);
    assert_eq!(
        eval(&s, "orgb:service:files", "files", "read", &escape),
        Decision::Deny
    );
    let inside = params(&[("file", Value::text("/home/agent/workspace/notes.txt"))]);
    assert_eq!(
        eval(&s, "orgb:service:files", "files", "read", &inside),
        Decision::Allow
    );
    // A mismatched audience.
    assert_eq!(
        eval(
            &s,
            "orgc:service:payments",
            "payments",
            "transfer",
            &transfer(500, "acct_vendor_a")
        ),
        Decision::Deny
    );
}

// ---- Remark 1, reflexivity, special forms ----

#[test]
fn remark_1_counterexample_is_rejected() {
    let s1 = Scope::parse(
        "allow at=v:service:v tool=t action=a params { x: int } where x <= 10
         allow at=v:service:v tool=t action=a params { x: int } where x > 10",
    )
    .unwrap();
    let s2 = Scope::parse("allow at=v:service:v tool=t action=a params { x: int }").unwrap();
    // Semantically contained (every x is ≤ 10 or > 10), but no single rule of
    // S1 subsumes S2's rule: the procedure is incomplete, conservatively.
    assert!(!contains(&s1, &s2));
    for x in [INT_MIN, -1, 10, 11, INT_MAX] {
        let prm = params(&[("x", Value::Int(x))]);
        assert_eq!(eval(&s1, "v:service:v", "t", "a", &prm), Decision::Allow);
    }
}

#[test]
fn reflexivity_including_recommended_order() {
    for src in [PAPER_6_2, RECOMMENDED_ORDER, "allow all", "deny all"] {
        let s = Scope::parse(src).unwrap();
        assert!(contains(&s, &s), "{src}");
    }
}

#[test]
fn special_forms_d24() {
    let rules = Scope::parse(PAPER_6_2).unwrap();
    // Soundness-critical: a rule list does not contain allow all (step 2).
    assert!(!contains(&rules, &Scope::allow_all()));
    // deny all contains nothing but deny all (step 3(a) finds no r1).
    assert!(!contains(&Scope::deny_all(), &rules));
    assert!(contains(&Scope::deny_all(), &Scope::deny_all()));
    assert!(contains(&Scope::allow_all(), &rules));
    assert!(contains(&rules, &Scope::deny_all()));
}

#[test]
fn step_3b_keeps_an_earlier_approval_requirement() {
    // Dropping the approval rule while keeping the permissive rule it shadows
    // is an escalation, and must be refused.
    let parent = Scope::parse(RECOMMENDED_ORDER).unwrap();
    let child = Scope::parse(
        "allow at=orgb:service:payments tool=payments action=transfer
           params { amount: int, to_account: string } where amount <= 1000",
    )
    .unwrap();
    assert!(!contains(&parent, &child));
    // Tightening a bound on the paper's order is contained.
    let parent = Scope::parse(PAPER_6_2).unwrap();
    let tightened = Scope::parse(&PAPER_6_2.replace("amount <= 1000", "amount <= 999")).unwrap();
    assert!(contains(&parent, &tightened));
    assert!(!contains(&tightened, &parent));
}

// ---- P-15 regression (SPEC §9.7) ----

const P15_CHILD: &str = r#"
allow at=orgb:service:payments tool=payments action=transfer
  params { amount: int, to_account: string }
  where amount <= 100000 and to_account in ["acct_vendor_a", "acct_vendor_b"]
        and z >= -18446744073709551616
  approval requires orga:approver:finance
allow at=orgb:service:payments tool=payments action=transfer
  params { amount: int, to_account: string }
  where amount <= 1000"#;

const P15_PARENT_DEAD: &str =
    "allow at=v:service:v tool=t action=a params { x: int } where z >= -18446744073709551616";
const P15_CHILD_LIVE: &str = "allow at=v:service:v tool=t action=a params { x: int }";

#[test]
fn p15_child_scope_is_malformed() {
    let m = malformed(P15_CHILD);
    assert!(m.contains("does not declare"), "{m}");
    let m = malformed(P15_PARENT_DEAD);
    assert!(m.contains("does not declare"), "{m}");
    // Also when it arrives as a CBOR AST, as it would inside a body.
    let unchecked = Scope::parse_unchecked(P15_CHILD).unwrap();
    assert!(matches!(
        Scope::from_value(&unchecked.to_value()),
        Err(PolicyError::Malformed(_))
    ));
    // And the bool tautology variant.
    malformed("allow at=v:service:v tool=t action=a params { x: int } where f in [true, false]");
}

#[test]
fn p15_pre_review_procedure_was_unsound() {
    // The bug, reproduced: the procedure without the well-formedness check
    // accepts both P-15 pairs, although a concrete invocation shows each child
    // is not contained.
    let parent = Scope::parse(RECOMMENDED_ORDER).unwrap();
    let child = Scope::parse_unchecked(P15_CHILD).unwrap();
    assert!(!child.is_well_formed());
    assert!(contains_pre_review(&parent, &child));
    let inv = transfer(500, "acct_vendor_a");
    let aud = "orgb:service:payments";
    assert_eq!(
        eval(&child, aud, "payments", "transfer", &inv),
        Decision::Allow
    );
    assert_eq!(
        eval(&parent, aud, "payments", "transfer", &inv),
        Decision::AllowWithApproval(vec![p("orga:approver:finance")])
    );

    let dead_parent = Scope::parse_unchecked(P15_PARENT_DEAD).unwrap();
    let live_child = Scope::parse(P15_CHILD_LIVE).unwrap();
    assert!(contains_pre_review(&dead_parent, &live_child));
    let x5 = params(&[("x", Value::uint(5))]);
    assert_eq!(
        eval(&live_child, "v:service:v", "t", "a", &x5),
        Decision::Allow
    );
    assert_eq!(
        eval(&dead_parent, "v:service:v", "t", "a", &x5),
        Decision::Deny
    );

    // With the fix, contains refuses both.
    assert!(!contains(&parent, &child));
    assert!(!contains(&dead_parent, &live_child));
}

// ---- well-formedness (paper §6.1) ----

#[test]
fn well_formedness_rules() {
    let head = "allow at=v:service:v tool=t action=a";
    let cases = [
        // Condition 3: kinds.
        ("allow at=v:agent:v tool=t action=a", "not a service"),
        (
            &format!("{head} approval requires orga:agent:x") as &str,
            "not an approver",
        ),
        // Condition 1: declarations.
        (
            &format!("{head} params {{ a: int, a.b: int }}"),
            "strict prefix",
        ),
        (
            &format!("{head} params {{ x: int }} where y == 1"),
            "does not declare",
        ),
        // Condition 2: operator, type and operand (D-20).
        (
            &format!("{head} params {{ x: int }} where x < \"a\""),
            "does not fit",
        ),
        (
            &format!("{head} params {{ x: int }} where x == true"),
            "does not fit",
        ),
        (
            &format!("{head} params {{ s: string }} where s < 3"),
            "does not fit",
        ),
        (
            &format!("{head} params {{ x: int }} where x starts_with \"a\""),
            "does not fit",
        ),
        (
            &format!("{head} params {{ x: int }} where x in [1, \"a\"]"),
            "does not fit",
        ),
        (
            &format!("{head} params {{ f: bool }} where f under \"/a\""),
            "does not fit",
        ),
        (
            &format!("{head} params {{ s: string }} where s under \"/a/../b\""),
            "canonical absolute",
        ),
        (
            &format!("{head} params {{ s: string }} where s under \"a/b\""),
            "canonical absolute",
        ),
        (
            &format!("{head} params {{ s: string }} where s under \"/a/\""),
            "canonical absolute",
        ),
    ];
    for (src, why) in cases {
        let m = malformed(src);
        assert!(m.contains(why), "{src}: {m}");
    }
    // Declared twice is a syntax error in the text form (a map cannot hold it).
    assert!(matches!(
        Scope::parse(&format!("{head} params {{ x: int, x: string }}")),
        Err(PolicyError::Syntax { .. })
    ));
    // Every compatible combination is accepted.
    Scope::parse(&format!(
        "{head} params {{ x: int, s: string, f: bool }} where x < 1 and x <= 1 and x == 1 and x >= 1 and x > 1 \
         and x in [1, 2] and s == \"a\" and s starts_with \"a\" and s ends_with \"a\" and s contains \"a\" \
         and s in [\"a\"] and s under \"/\" and f == true and f in [true, false]"
    ))
    .unwrap();
}

#[test]
fn size_limits_d21() {
    let rule = "allow at=v:service:v tool=t action=a\n";
    assert!(Scope::parse(&rule.repeat(256)).is_ok());
    assert!(malformed(&rule.repeat(257)).contains("more than 256 rules"));
    let many: Vec<String> = (0..33).map(|i| format!("p{i}: int")).collect();
    assert!(
        malformed(&format!(
            "allow at=v:service:v tool=t action=a params {{ {} }}",
            many.join(", ")
        ))
        .contains("parameters")
    );
    let list: Vec<String> = (0..65).map(|i| i.to_string()).collect();
    assert!(
        malformed(&format!(
            "allow at=v:service:v tool=t action=a params {{ x: int }} where x in [{}]",
            list.join(",")
        ))
        .contains("1 to 64")
    );
    assert!(
        malformed("allow at=v:service:v tool=t action=a params { a.b.c.d.e.f.g.h.i: int }")
            .contains("path grammar")
    );
    let long = "a".repeat(1025);
    assert!(
        malformed(&format!(
            "allow at=v:service:v tool=t action=a params {{ s: string }} where s == \"{long}\""
        ))
        .contains("1024")
    );
}

#[test]
fn ast_level_rules() {
    let good = Scope::parse("allow at=v:service:v tool=t action=a params { x: int } where x < 3 approval requires o:approver:a, o:approver:b").unwrap();
    let v = good.to_value();
    assert_eq!(Scope::from_value(&v).unwrap(), good);
    let rule = |f: &dyn Fn(&mut RuleMap)| {
        let mut v = v.clone();
        let Value::Map(top) = &mut v else { panic!() };
        let Value::Array(rules) = &mut top[1].1 else {
            panic!()
        };
        let Value::Map(r) = &mut rules[0] else {
            panic!()
        };
        f(r);
        Scope::from_value(&v)
    };
    // Unsorted, or duplicated, approvals.
    let bad = rule(&|r| {
        r[5].1 = Value::Array(vec![
            Value::text("o:approver:b"),
            Value::text("o:approver:a"),
        ])
    });
    assert!(matches!(bad, Err(PolicyError::Malformed(_))));
    let bad = rule(&|r| {
        r[5].1 = Value::Array(vec![
            Value::text("o:approver:a"),
            Value::text("o:approver:a"),
        ])
    });
    assert!(matches!(bad, Err(PolicyError::Malformed(_))));
    // Present but empty params, atoms, approval.
    for k in [3usize, 4, 5] {
        let bad = rule(&|r| {
            r[k].1 = if k == 3 {
                Value::Map(vec![])
            } else {
                Value::Array(vec![])
            }
        });
        assert!(
            matches!(bad, Err(PolicyError::Malformed(_))),
            "key {}",
            k + 1
        );
    }
    // Unknown operator and type codes, unknown keys.
    let bad = rule(&|r| {
        r[4].1 = Value::Array(vec![Value::Array(vec![
            Value::uint(10),
            Value::text("x"),
            Value::uint(1),
        ])])
    });
    assert!(matches!(bad, Err(PolicyError::Malformed(_))));
    let bad = rule(&|r| r[3].1 = Value::map(vec![(Key::from("x"), Value::uint(3))]).unwrap());
    assert!(matches!(bad, Err(PolicyError::Malformed(_))));
    let bad = rule(&|r| r.push((Key::Uint(7), Value::Null)));
    assert!(matches!(bad, Err(PolicyError::Malformed(_))));
    // Special forms carry nothing else; an empty rule list is malformed.
    let extra = Value::map(vec![
        (Key::Uint(1), Value::uint(0)),
        (Key::Uint(2), Value::Array(vec![])),
    ])
    .unwrap();
    assert!(Scope::from_value(&extra).is_err());
    let empty = Value::map(vec![
        (Key::Uint(1), Value::uint(2)),
        (Key::Uint(2), Value::Array(vec![])),
    ])
    .unwrap();
    assert!(Scope::from_value(&empty).is_err());
}

#[test]
fn policy_documents_decode_strictly() {
    let s = Scope::parse(PAPER_6_2).unwrap();
    let bytes = s.canonical_bytes();
    assert_eq!(Scope::decode_policy(&bytes).unwrap(), s);
    assert_eq!(s.policy_hash(), dc_types::digest::policy_hash(&bytes));
    // Non-canonical CBOR: the top-level map head written in two bytes.
    let mut nc = bytes.clone();
    nc.splice(0..1, [0xb8, 0x02]);
    assert!(Scope::decode_policy(&nc).is_err());
    // Non-NFC text is malformed in a policy document (D-55).
    let decomposed = Scope::parse("allow at=v:service:v tool=t action=a params { s: string } where s == \"caf\\u0065\\u0301\"").unwrap();
    let mut v = decomposed.to_value();
    let Value::Map(top) = &mut v else { panic!() };
    let Value::Array(rules) = &mut top[1].1 else {
        panic!()
    };
    let Value::Map(r) = &mut rules[0] else {
        panic!()
    };
    r[4].1 = Value::Array(vec![Value::Array(vec![
        Value::uint(2),
        Value::text("s"),
        Value::text("cafe\u{301}"),
    ])]);
    let raw = dc_cbor::encode(&v).unwrap();
    assert!(
        Scope::decode_policy(&raw)
            .unwrap_err()
            .to_string()
            .contains("NFC")
    );
}

// ---- parser (D-17) ----

#[test]
fn lexical_details() {
    let s = Scope::parse(
        "allow at=v:service:v tool=t action=a params{s:string,x:int}where(s==\"a\\\"b\\\\c\\/\\n\\u00e9\\ud83d\\ude00\"and x>=-18446744073709551616)and x<=18446744073709551615",
    )
    .unwrap();
    let ScopeForm::Rules(r) = s.form() else {
        panic!()
    };
    assert_eq!(r[0].atoms.len(), 3);
    assert_eq!(
        r[0].atoms[0].operand,
        dc_policy::Operand::One(Literal::Str("a\"b\\c/\n\u{e9}\u{1f600}".into()))
    );
    assert_eq!(
        r[0].atoms[1].operand,
        dc_policy::Operand::One(Literal::Int(INT_MIN))
    );
    assert_eq!(
        r[0].atoms[2].operand,
        dc_policy::Operand::One(Literal::Int(INT_MAX))
    );
    // String literals are NFC-normalized (paper §6.1).
    let s = Scope::parse(
        "allow at=v:service:v tool=t action=a params { s: string } where s == \"cafe\\u0301\"",
    )
    .unwrap();
    let ScopeForm::Rules(r) = s.form() else {
        panic!()
    };
    assert_eq!(
        r[0].atoms[0].operand,
        dc_policy::Operand::One(Literal::Str("caf\u{e9}".into()))
    );
    // Errors.
    for bad in [
        "allow at=v:service:v tool=t action=a params { x: int } where x < 18446744073709551616",
        "allow at=v:service:v tool=t action=a params { x: int } where x < -18446744073709551617",
        "allow at=v:service:v tool=t action=a params { s: string } where s == \"unterminated",
        "allow at=v:service:v tool=t action=a params { s: string } where s == \"\\ud83d\"",
        "allow at=v:service:v tool=t action=a params { s: string } where s == \"\\q\"",
        "allow at=v:service:v tool=t",
        "allow at=v:service tool=t action=a",
        "allow at=v:robot:v tool=t action=a",
        "allow all allow at=v:service:v tool=t action=a",
        "",
        "allow at=v:service:v tool=t action=a params { s: string } where s starts_with 3",
        "allow at=v:service:v tool=t action=a params { x: int } where x @ 3",
    ] {
        assert!(
            matches!(Scope::parse(bad), Err(PolicyError::Syntax { .. })),
            "{bad:?} gave {:?}",
            Scope::parse(bad)
        );
    }
}

#[test]
fn keywords_are_contextual() {
    let s = Scope::parse(
        "allow at=v:service:v tool=params action=where params { in: int, approval: bool, and: string }
           where in == 3 and approval == true and and == \"x\" approval requires o:approver:a",
    )
    .unwrap();
    let ScopeForm::Rules(r) = s.form() else {
        panic!()
    };
    assert_eq!(r[0].atoms.len(), 3);
    assert_eq!(r[0].approval.len(), 1);
    assert_eq!(Scope::parse(&s.to_string()).unwrap(), s);
}

#[test]
fn printer_round_trips_the_paper_example() {
    let s = Scope::parse(PAPER_6_2).unwrap();
    assert_eq!(Scope::parse(&s.to_string()).unwrap(), s);
    assert_eq!(Scope::from_value(&s.to_value()).unwrap(), s);
}

// ---- evaluation details (paper §6.3; D-23) ----

#[test]
fn closed_world_and_untyped_leaves() {
    let s = Scope::parse("allow at=v:service:v tool=t action=a params { x: int, o.y: string }")
        .unwrap();
    let ok = params(&[
        ("x", Value::uint(1)),
        ("o", params(&[("y", Value::text("a"))])),
    ]);
    assert_eq!(eval(&s, "v:service:v", "t", "a", &ok), Decision::Allow);
    let cases = [
        params(&[("x", Value::uint(1))]), // missing o.y
        params(&[
            ("x", Value::text("1")),
            ("o", params(&[("y", Value::text("a"))])),
        ]), // wrong type
        params(&[
            ("x", Value::Null),
            ("o", params(&[("y", Value::text("a"))])),
        ]), // untyped
        params(&[
            ("x", Value::bytes(vec![1])),
            ("o", params(&[("y", Value::text("a"))])),
        ]),
        params(&[
            ("x", Value::Array(vec![Value::uint(1)])),
            ("o", params(&[("y", Value::text("a"))])),
        ]),
        params(&[("x", Value::uint(1)), ("o", Value::Map(vec![]))]), // empty map leaf
        params(&[
            ("x", Value::uint(1)),
            (
                "o",
                params(&[("y", Value::text("a")), ("z", Value::uint(0))]),
            ),
        ]),
        params(&[
            ("x", Value::uint(1)),
            ("o", params(&[("y", Value::text("a"))])),
            ("bad key", Value::uint(0)),
        ]),
        params(&[
            ("x", Value::uint(1)),
            ("o", params(&[("y", Value::text("a"))])),
            ("a.b", Value::uint(0)),
        ]),
    ];
    for c in cases {
        assert_eq!(
            eval(&s, "v:service:v", "t", "a", &c),
            Decision::Deny,
            "{c:?}"
        );
    }
    // No params declared: matches only the empty map.
    let s = Scope::parse("allow at=v:service:v tool=t action=a").unwrap();
    assert_eq!(
        eval(&s, "v:service:v", "t", "a", &Value::Map(vec![])),
        Decision::Allow
    );
    assert_eq!(
        eval(
            &s,
            "v:service:v",
            "t",
            "a",
            &params(&[("x", Value::uint(1))])
        ),
        Decision::Deny
    );
}

#[test]
fn under_and_string_operators() {
    let s = Scope::parse("allow at=v:service:v tool=t action=a params { f: string } where f under \"/home/agent/workspace\"").unwrap();
    let f = |v: &str| {
        eval(
            &s,
            "v:service:v",
            "t",
            "a",
            &params(&[("f", Value::text(v))]),
        )
    };
    assert_eq!(f("/home/agent/workspace"), Decision::Allow); // equality counts (D-22)
    assert_eq!(f("/home/agent/workspace/a/b"), Decision::Allow);
    assert_eq!(f("/home/agent/workspace-evil"), Decision::Deny);
    assert_eq!(f("/home/agent/workspace/"), Decision::Deny); // trailing slash: not canonical
    assert_eq!(f("/home/agent/workspace//a"), Decision::Deny);
    assert_eq!(f("/home/agent/workspace/./a"), Decision::Deny);
    assert_eq!(f("home/agent/workspace/a"), Decision::Deny);
    let root = Scope::parse(
        "allow at=v:service:v tool=t action=a params { f: string } where f under \"/\"",
    )
    .unwrap();
    assert_eq!(
        eval(
            &root,
            "v:service:v",
            "t",
            "a",
            &params(&[("f", Value::text("/"))])
        ),
        Decision::Allow
    );
    assert_eq!(
        eval(
            &root,
            "v:service:v",
            "t",
            "a",
            &params(&[("f", Value::text("/x"))])
        ),
        Decision::Allow
    );

    let s = Scope::parse("allow at=v:service:v tool=t action=a params { s: string } where s starts_with \"ab\" and s ends_with \"yz\" and s contains \"mm\"").unwrap();
    let f = |v: &str| {
        eval(
            &s,
            "v:service:v",
            "t",
            "a",
            &params(&[("s", Value::text(v))]),
        )
    };
    assert_eq!(f("abmmyz"), Decision::Allow);
    assert_eq!(f("abyz"), Decision::Deny);
}

#[test]
fn first_match_wins_and_approvals_are_sorted() {
    let s = Scope::parse(
        "allow at=v:service:v tool=t action=a params { x: int } where x < 5 approval requires o:approver:b, o:approver:a
         allow at=v:service:v tool=t action=a params { x: int }",
    )
    .unwrap();
    assert_eq!(
        eval(
            &s,
            "v:service:v",
            "t",
            "a",
            &params(&[("x", Value::uint(1))])
        ),
        Decision::AllowWithApproval(vec![p("o:approver:a"), p("o:approver:b")])
    );
    assert_eq!(
        eval(
            &s,
            "v:service:v",
            "t",
            "a",
            &params(&[("x", Value::uint(9))])
        ),
        Decision::Allow
    );
    assert_eq!(
        eval(&Scope::allow_all(), "x:service:y", "t", "a", &Value::Null),
        Decision::Allow
    );
    assert_eq!(
        eval(
            &Scope::deny_all(),
            "x:service:y",
            "t",
            "a",
            &Value::Map(vec![])
        ),
        Decision::Deny
    );
}
