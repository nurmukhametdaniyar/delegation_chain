//! Q8: Evaluate and Contains as scope size grows (SPEC §13.5), for
//! rules ∈ {1, 4, 16, 64} × atoms ∈ {1, 4, 8} (D-73).
//!
//! Every rule has the same head and 8 declared integer parameters. Rule i's
//! atoms bound x0 … x(a−2) by 1,000 and require x(a−1) == i, so a rule
//! fails only at its last atom.
//! - Evaluate, typical: the first rule matches. Worst: only the last rule
//!   matches, after every earlier rule has evaluated all its atoms.
//! - Contains, typical: the child equals the parent. Worst: every child
//!   rule's bounds are tightened, so no child rule is trivially equal to
//!   its parent rule.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use dc_cbor::{Key, Value};
use dc_policy::{Invocation, Scope, contains, evaluate};
use dc_types::{Identifier, Principal};

fn scope(rules: usize, atoms: usize, bound: u64) -> Scope {
    let params: Vec<String> = (0..8).map(|j| format!("x{j}: int")).collect();
    let text: Vec<String> = (0..rules)
        .map(|i| {
            let mut conds: Vec<String> =
                (0..atoms - 1).map(|j| format!("x{j} <= {bound}")).collect();
            conds.push(format!("x{} == {i}", atoms - 1));
            format!(
                "allow at=orgb:service:s\n  tool=t action=a\n  params {{ {} }}\n  where {}",
                params.join(", "),
                conds.join(" and ")
            )
        })
        .collect();
    Scope::parse(&text.join("\n")).expect("well formed")
}

fn params(atoms: usize, target: usize) -> Value {
    let entries: Vec<(Key, Value)> = (0..8)
        .map(|j| {
            let v = if j == atoms - 1 { target as u64 } else { 10 };
            (Key::from(format!("x{j}").as_str()), Value::uint(v))
        })
        .collect();
    Value::map(entries).expect("distinct keys")
}

fn bench(c: &mut Criterion) {
    let aud = Principal::parse("orgb:service:s").unwrap();
    let tool = Identifier::new("t").unwrap();
    let action = Identifier::new("a").unwrap();
    let mut eval = c.benchmark_group("policy/evaluate");
    for rules in [1, 4, 16, 64] {
        for atoms in [1, 4, 8] {
            let s = scope(rules, atoms, 1000);
            for (case, target) in [("typical", 0), ("worst", rules - 1)] {
                let p = params(atoms, target);
                let inv = Invocation {
                    aud: &aud,
                    tool: &tool,
                    action: &action,
                    params: &p,
                };
                assert!(evaluate(&s, &inv) != dc_policy::Decision::Deny);
                eval.bench_with_input(
                    BenchmarkId::new(case, format!("r{rules}_a{atoms}")),
                    &(),
                    |b, _| b.iter(|| evaluate(black_box(&s), black_box(&inv))),
                );
            }
        }
    }
    eval.finish();
    let mut cont = c.benchmark_group("policy/contains");
    for rules in [1, 4, 16, 64] {
        for atoms in [1, 4, 8] {
            let parent = scope(rules, atoms, 1000);
            for (case, child) in [
                ("typical", scope(rules, atoms, 1000)),
                ("worst", scope(rules, atoms, 999)),
            ] {
                assert!(contains(&parent, &child));
                cont.bench_with_input(
                    BenchmarkId::new(case, format!("r{rules}_a{atoms}")),
                    &(),
                    |b, _| b.iter(|| contains(black_box(&parent), black_box(&child))),
                );
            }
        }
    }
    cont.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
