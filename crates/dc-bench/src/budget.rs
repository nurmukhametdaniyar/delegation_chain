//! D-100's exploratory measurement, not in the frozen plan: what the work
//! budget of `Contains` (SPEC §9.6.1) leaves a compromised signer, at the
//! default budget.
//!
//! - **`Contains` at the budget** (`benches/budget_cost.rs`, group
//!   `budget-cost/contains`): every input of D-98's search, and paddings
//!   that are slow per counted unit (long strings, wide heads, many
//!   approvers; [`pads`]), each at the most rules that fit a body, and the
//!   frozen generator's worst case at every cell that fits. The unit does
//!   not count text lengths, head comparisons or approval comparisons, so
//!   the time per unit varies by input; the costliest measured is a lower
//!   bound on the ceiling.
//! - **Line 2 on a 64 KiB scope body** (`budget-cost/line2`, and line 5's
//!   re-encoding as `budget-cost/line5`): delegation bodies whose scope
//!   fills the body in several ways ([`body_scopes`]). Line 2 runs before
//!   any signature, so an unsigned chain can make the verifier do it for
//!   every body.
//! - **The frozen generator's shapes the default admits** ([`counts`]):
//!   deterministic counts, not timings.
//!
//! Per chain at N = 16: [`LINKS`] containment links whose child a
//! compromised agent signs, and [`SCOPE_BODIES`] bodies that carry a scope.

use std::fmt::Write as _;
use std::path::Path;

use dc_crypto::{Ed25519, Ed25519List};
use dc_policy::{DEFAULT_BUDGET, Scope, contains_within};
use dc_types::{Body, Envelope, decode_body};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Value, json};

use crate::bounds::{
    COST_CELLS, Pad, SHORT_HEAD, fits, frozen_worst, max_rules, padded, search_pads,
};
use crate::contains_cost::ms;
use crate::reorder;
use crate::report::{criterion_estimates, read_json};
use crate::workload::{Profile, Setting, hop_scopes};

/// Links at N = 16 whose child scope a compromised agent signs: delegations
/// 1–15. Line 35's link, the pinned policy against the issuer's session
/// scope, is honest. Each link can cost up to the budget, whichever side
/// drives the work, so the ceiling counts all 15 (D-98 counted the 14 whose
/// parent the agent also signs).
pub const LINKS: usize = 15;

/// Bodies at N = 16 that carry a scope: the session and delegations 1–15.
pub const SCOPE_BODIES: usize = 16;

/// Atom counts at which every padding is tried.
pub const ATOMS: [usize; 5] = [4, 8, 16, 24, 32];

/// D-98's paddings, and D-100's, which are slow per counted unit.
pub fn pads() -> Vec<Pad> {
    let mut v = search_pads();
    for b in [64, 256, 960] {
        v.extend([Pad::StrContains(b), Pad::StrSuffix(b), Pad::StrUnder(b)]);
    }
    // Members of up to 1,019 bytes (`SetContains`) or 1,021 (`SetUnder`).
    for (n, b) in [(4, 1016), (8, 1016), (16, 1016), (32, 256), (64, 64)] {
        v.extend([Pad::SetContains(n, b), Pad::SetUnder(n, b)]);
    }
    v.extend([
        Pad::Decl(8),
        Pad::Decl(64),
        Pad::Approvals(16),
        Pad::Approvals(128),
    ]);
    v
}

/// [`pads`], and D-101's paddings aimed at what its unit newly charges:
/// long heads, long declared paths and long approver names.
pub fn pads_d101() -> Vec<Pad> {
    let mut v = pads();
    v.extend([
        Pad::Head(1000),
        Pad::Decl(1000),
        Pad::LongApprovals(8),
        Pad::LongApprovals(32),
    ]);
    v
}

/// Every timed `Contains` input: (label, parent, child).
pub fn contains_inputs() -> Vec<(String, Scope, Scope)> {
    contains_inputs_for(&pads())
}

/// The frozen generator's worst case at every D-98 cell that fits, and
/// every padding of `pads` at the most rules that fit with each of
/// [`ATOMS`] atoms a rule.
pub fn contains_inputs_for(pads: &[Pad]) -> Vec<(String, Scope, Scope)> {
    let mut v = vec![];
    for (rules, atoms) in COST_CELLS {
        let (p, c) = (
            frozen_worst(rules, atoms, 1000),
            frozen_worst(rules, atoms, 999),
        );
        if fits(&p) && fits(&c) {
            v.push((format!("frozen-worst/r{rules}_a{atoms}"), p, c));
        }
    }
    for &pad in pads {
        for atoms in ATOMS {
            if let Some(rules) = max_rules(pad, atoms) {
                v.push((
                    format!("{}/r{rules}_a{atoms}", pad.label()),
                    padded(pad, rules, atoms, false),
                    padded(pad, rules, atoms, true),
                ));
            }
        }
    }
    v
}

/// One way to fill a scope body, as a function of its size parameter.
struct Fill {
    label: &'static str,
    /// The largest size parameter tried.
    max: usize,
    text: fn(usize) -> String,
}

fn rules_of(rule: &str, n: usize) -> String {
    vec![rule; n].join("\n")
}

const STR_HEAD: &str = "allow at=o:service:s tool=t action=a params { s: string }";

fn fills() -> Vec<Fill> {
    vec![
        // The most atoms: 32 small bounds a rule.
        Fill {
            label: "atoms",
            max: 256,
            text: |n| {
                let a: Vec<String> = (0..32).map(|k| format!("x <= {k}")).collect();
                rules_of(&format!("{SHORT_HEAD} where {}", a.join(" and ")), n)
            },
        },
        // The most literals: 64-element integer lists.
        Fill {
            label: "intlists",
            max: 256,
            text: |n| {
                let l: Vec<String> = (0..64).map(|v| v.to_string()).collect();
                let a = vec![format!("x in [{}]", l.join(", ")); 32];
                rules_of(&format!("{SHORT_HEAD} where {}", a.join(" and ")), n)
            },
        },
        // Text items of q + U+0301 after a number: NFC (no precomposed q
        // with acute exists), but only a full check shows it.
        Fill {
            label: "strlists-nfc-maybe",
            max: 256,
            text: |n| {
                let l: Vec<String> = (0..64).map(|v| format!("\"{v}q\u{301}\"")).collect();
                let a = vec![format!("s in [{}]", l.join(", ")); 32];
                rules_of(&format!("{STR_HEAD} where {}", a.join(" and ")), n)
            },
        },
        // The most text items: 64-element lists of one-letter strings.
        Fill {
            label: "strlists",
            max: 256,
            text: |n| {
                let l: Vec<String> = (0..64)
                    .map(|v| format!("\"{}\"", (b'a' + (v % 26) as u8) as char))
                    .collect();
                let a = vec![format!("s in [{}]", l.join(", ")); 32];
                rules_of(&format!("{STR_HEAD} where {}", a.join(" and ")), n)
            },
        },
        // The most declared paths: 32 a rule, 8 segments deep.
        Fill {
            label: "params",
            max: 256,
            text: |n| {
                let p: Vec<String> = (0..32)
                    .map(|k| format!("a.b.c.d.e.f.g.p{k:02}: int"))
                    .collect();
                rules_of(
                    &format!(
                        "allow at=o:service:s tool=t action=a params {{ {} }}",
                        p.join(", ")
                    ),
                    n,
                )
            },
        },
        // The most approvers, in one rule.
        Fill {
            label: "approvals",
            max: 16384,
            text: |n| {
                let a: Vec<String> = (0..n).map(|k| format!("o:approver:a{k:04}")).collect();
                format!("{SHORT_HEAD} approval requires {}", a.join(", "))
            },
        },
        // 1,024-byte ASCII strings.
        Fill {
            label: "text-ascii",
            max: 256,
            text: |n| text_atoms(n, &"a".repeat(1024)),
        },
        // 1,023-byte strings of q + U+0301: NFC, but only a full check shows
        // it (the quick check answers "maybe").
        Fill {
            label: "text-nfc-maybe",
            max: 256,
            text: |n| text_atoms(n, &"q\u{301}".repeat(341)),
        },
        // 1,022-byte canonical paths of 511 segments under `under`.
        Fill {
            label: "under-paths",
            max: 256,
            text: |n| {
                let q = "/a".repeat(511);
                let a: Vec<String> = (0..n).map(|_| format!("s under \"{q}\"")).collect();
                a.chunks(32)
                    .map(|c| format!("{STR_HEAD} where {}", c.join(" and ")))
                    .collect::<Vec<_>>()
                    .join("\n")
            },
        },
    ]
}

/// `n` atoms `s == text`, 32 to a rule.
fn text_atoms(n: usize, text: &str) -> String {
    let a: Vec<String> = (0..n).map(|_| format!("s == \"{text}\"")).collect();
    a.chunks(32)
        .map(|c| format!("{STR_HEAD} where {}", c.join(" and ")))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every line-2 input: (label, a scope that fills a body).
pub fn body_scopes() -> Vec<(String, Scope)> {
    body_scopes_within(256, dc_cbor::MAX_BODY_SIZE)
}

/// The rules of a scope (0 for `allow all` and `deny all`).
pub fn rule_count(s: &Scope) -> usize {
    match s.form() {
        dc_policy::ScopeForm::Rules(r) => r.len(),
        _ => 0,
    }
}

/// [`body_scopes`] with at most `max_rules` rules a scope, and bodies of at
/// most `max_body` bytes with [`BODY_SPARE`] to spare (D-101's proposed
/// limits).
pub fn body_scopes_within(max_rules: usize, max_body: usize) -> Vec<(String, Scope)> {
    let ok = |s: &Scope| {
        rule_count(s) <= max_rules
            && s.canonical_bytes().len() + crate::bounds::BODY_SPARE <= max_body
    };
    fills()
        .into_iter()
        .map(|f| {
            let scope = |n| Scope::parse(&(f.text)(n)).expect("well formed");
            let (mut lo, mut hi) = (1usize, f.max);
            assert!(ok(&scope(1)), "{}: one unit fits", f.label);
            while lo < hi {
                let mid = (lo + hi).div_ceil(2);
                if ok(&scope(mid)) {
                    lo = mid;
                } else {
                    hi = mid - 1;
                }
            }
            (f.label.to_owned(), scope(lo))
        })
        .collect()
}

/// A delegation body carrying `scope`, otherwise one of the medium
/// profile's (D-71's setting), in canonical form. Its signatures are
/// irrelevant to line 2.
pub fn delegation_body(setting: &Setting<Ed25519>, scope: &Scope) -> Vec<u8> {
    delegation_body_within(setting, scope, dc_cbor::MAX_BODY_SIZE)
}

/// [`delegation_body`] for a body limit of `max` bytes (D-101's proposed
/// limits).
pub fn delegation_body_within(setting: &Setting<Ed25519>, scope: &Scope, max: usize) -> Vec<u8> {
    let mut rng = ChaCha20Rng::seed_from_u64(0xD100);
    let (b, holder) = setting.prefix::<Ed25519List>(Profile::Medium, 2, 0, &mut rng);
    let chain = setting.invoke(Profile::Medium, &b, &holder, &mut rng);
    let env = Envelope::from_bytes(&chain).expect("envelope");
    let mut d = decode_body::<Ed25519>(&env.bodies[1]).expect("body").body;
    let Body::Delegation(del) = &mut d else {
        panic!("body 1 is a delegation")
    };
    del.scope = scope.to_raw();
    let bytes = d.canonical_bytes().expect("encodes");
    assert!(bytes.len() <= max, "fits a body");
    bytes
}

/// Line 2 for one body, as the verifier runs it: decode the body under its
/// own kind, then decode and validate its scope (D-28, D-32).
pub fn line2(bytes: &[u8]) -> Option<Scope> {
    line2_within(bytes, dc_cbor::MAX_BODY_SIZE)
}

/// [`line2`] with a body limit of `max` bytes (D-101's proposed limits).
pub fn line2_within(bytes: &[u8], max: usize) -> Option<Scope> {
    let limits = dc_cbor::Limits {
        max_size: max,
        ..dc_cbor::Limits::BODY
    };
    let d = dc_types::decode_body_within::<Ed25519>(bytes, limits).ok()?;
    d.body.scope().map(Scope::from_raw)?.ok()
}

/// Line 5 for a decoded body: no recorded violation, and the re-encoding
/// equals the bytes received (D-31).
pub fn line5(body: &dc_types::DecodedBody<Ed25519>, bytes: &[u8]) -> bool {
    body.violation.is_none() && body.body.canonical_bytes().is_ok_and(|b| b == bytes)
}

/// The deterministic part of D-100's measurement, for `work.json`: each
/// timed input's count under the default budget, the frozen generator's
/// shapes the default admits, and the workload profiles' largest count.
pub fn counts() -> serde_json::Value {
    let inputs: serde_json::Map<String, serde_json::Value> = contains_inputs()
        .into_iter()
        .map(|(label, p, c)| {
            let w = contains_within(&p, &c, DEFAULT_BUDGET);
            (
                label,
                json!({ "work": w.work, "exhausted": w.exhausted, "answer": w.answer }),
            )
        })
        .collect();
    let setting = Setting::<Ed25519>::new();
    let bodies: serde_json::Map<String, serde_json::Value> = body_scopes()
        .into_iter()
        .map(|(label, s)| {
            let body = delegation_body(&setting, &s);
            (
                label,
                json!({ "scope_bytes": s.canonical_bytes().len(), "body_bytes": body.len() }),
            )
        })
        .collect();
    let profiles_max = Profile::ALL
        .iter()
        .flat_map(|&p| {
            let s = hop_scopes(p);
            let mut w = vec![contains_within(&s[0], &s[0], u64::MAX).work];
            w.extend((1..s.len()).map(|k| contains_within(&s[k - 1], &s[k], u64::MAX).work));
            w
        })
        .max();
    json!({
        "label": "D-100: counts under the default work budget; deterministic, not timings",
        "default_budget": DEFAULT_BUDGET,
        "profiles_max_work": profiles_max,
        "inputs": inputs,
        "bodies": bodies,
        "admitted_frozen_shapes": admitted(),
    })
}

/// For each atom count, the most rules of the frozen generator's shape
/// whose three checks stay within the default budget: the pin-time check
/// on the policy, the link from the policy to a child scope one tighter
/// (the D-98 frozen-worst pair), and the child's own reflexive check (an
/// agent that re-delegates its whole scope). Only shapes that fit a body.
fn admitted() -> serde_json::Value {
    let ok = |s1: &Scope, s2: &Scope| !contains_within(s1, s2, DEFAULT_BUDGET).exhausted;
    let rows: Vec<serde_json::Value> = [1usize, 2, 4, 8, 16, 32]
        .into_iter()
        .map(|atoms| {
            let mut admitted = vec![];
            let mut largest_fitting = 0;
            for rules in 1..=256 {
                let (p, c) = (
                    frozen_worst(rules, atoms, 1000),
                    frozen_worst(rules, atoms, 999),
                );
                if !(fits(&p) && fits(&c)) {
                    break;
                }
                largest_fitting = rules;
                if ok(&p, &p) && ok(&p, &c) && ok(&c, &c) {
                    admitted.push(rules);
                }
            }
            let max = admitted.last().copied().unwrap_or(0);
            let work = |rules: usize| {
                let (p, c) = (
                    frozen_worst(rules, atoms, 1000),
                    frozen_worst(rules, atoms, 999),
                );
                [
                    contains_within(&p, &p, u64::MAX).work,
                    contains_within(&p, &c, u64::MAX).work,
                    contains_within(&c, &c, u64::MAX).work,
                ]
            };
            json!({
                "atoms": atoms,
                "largest_fitting_rules": largest_fitting,
                "max_admitted_rules": max,
                "contiguous": admitted.len() == max,
                "work_at_max": (max > 0).then(|| work(max)),
                "work_one_more": (max > 0 && max < largest_fitting).then(|| work(max + 1)),
            })
        })
        .collect();
    json!(rows)
}

/// D-100's results, from `results/exploratory/budget/`.
pub struct Data {
    /// (criterion id, median ns, CI).
    est: Vec<(String, f64, (f64, f64))>,
    work: Value,
    oracle: Value,
    /// The headline check's three builds, once archived.
    pub headline: Option<reorder::Data>,
}

pub fn load(dir: &Path) -> Result<Data, String> {
    let est = criterion_estimates(&dir.join("criterion"));
    if est.is_empty() {
        return Err(format!(
            "no criterion estimates under {}/criterion: unpack criterion.tar.zst (ARTIFACT.md §3)",
            dir.display()
        ));
    }
    let need = |f: &str| read_json(&dir.join(f)).ok_or_else(|| format!("no {}/{f}", dir.display()));
    let hdir = dir.join("headline");
    let headline = if hdir.join("budgeted/archive/MANIFEST.sha256").exists() {
        Some(reorder::load(&hdir, reorder::BUDGET)?)
    } else {
        None
    };
    Ok(Data {
        est,
        work: need("work.json")?,
        oracle: need("oracle.json")?,
        headline,
    })
}

/// An input's family: its label up to the first digit or `/`.
fn family(key: &str) -> &str {
    let end = key
        .find(|c: char| c.is_ascii_digit() || c == '/')
        .unwrap_or(key.len());
    &key[..end]
}

impl Data {
    /// (key without the group's prefix, median ns, CI) of one kind.
    fn of(&self, kind: &str) -> Vec<(&str, f64, (f64, f64))> {
        let prefix = format!("budget-cost/{kind}/");
        let mut v: Vec<_> = self
            .est
            .iter()
            .filter_map(|(id, m, ci)| Some((id.strip_prefix(&prefix)?, *m, *ci)))
            .collect();
        v.sort_by(|a, b| b.1.total_cmp(&a.1));
        v
    }

    /// The input's count under the default budget, as `work.json` gives it.
    fn count(&self, key: &str) -> String {
        let i = &self.work["inputs"][key];
        match (i["exhausted"].as_bool(), i["work"].as_u64()) {
            (Some(true), _) => "over the budget".into(),
            (Some(false), Some(w)) => format!("{w}"),
            _ => "?".into(),
        }
    }

    /// The costliest `Contains` call and line-2 body: (key, ns) each.
    fn worst(&self) -> Option<((String, f64), (String, f64))> {
        let c = self.of("contains").first().map(|e| (e.0.to_owned(), e.1))?;
        let l = self.of("line2").first().map(|e| (e.0.to_owned(), e.1))?;
        Some((c, l))
    }

    /// The per-link ceiling and the per-chain one, in ns: `Contains` at the
    /// budget plus line 2 on one body, and over [`LINKS`] links and
    /// [`SCOPE_BODIES`] bodies.
    pub fn ceiling(&self) -> Option<(f64, f64)> {
        let ((_, c), (_, l)) = self.worst()?;
        Some((c + l, LINKS as f64 * c + SCOPE_BODIES as f64 * l))
    }

    /// BENCHMARKS.md §8's block for D-100. `strict` is one strict Ed25519
    /// verification, in ns; `m9` as for [`reorder::Data::markdown`].
    pub fn markdown(&self, strict: f64, m9: &dyn Fn(&str, &str) -> Option<f64>) -> String {
        let mut w = String::new();
        let x = |ns: f64| format!("{:.0}", ns / strict);
        let budget = self.work["default_budget"].as_u64().unwrap_or(0);
        let contains = self.of("contains");
        writeln!(
            w,
            "**`Contains` at the default budget ({budget}),** the ten costliest of {} inputs (ms; the count W, or *over the budget*):\n\n| Input | W | Median [95% CI] |\n|---|---|---|",
            contains.len()
        )
        .unwrap();
        for (k, m, ci) in contains.iter().take(10) {
            writeln!(
                w,
                "| {k} | {} | {} [{}, {}] |",
                self.count(k),
                ms(*m),
                ms(ci.0),
                ms(ci.1)
            )
            .unwrap();
        }
        w.push_str("\n**The costliest input of each family** (ms):\n\n| Family | Input | W | Median |\n|---|---|---|---|\n");
        let mut seen: Vec<&str> = vec![];
        let mut rows: Vec<String> = vec![];
        for (k, m, _) in &contains {
            let f = family(k);
            if !seen.contains(&f) {
                seen.push(f);
                rows.push(format!("| {f} | {k} | {} | {} |", self.count(k), ms(*m)));
            }
        }
        w.push_str(&rows.join("\n"));
        w.push('\n');
        w.push_str("\n**Lines 2 and 5 on one scope body** filled toward 64 KiB (ms):\n\n| Body | Bytes | Line 2 | Line 5 |\n|---|---|---|---|\n");
        let line5 = self.of("line5");
        for (k, m, ci) in self.of("line2") {
            let l5 = line5
                .iter()
                .find(|e| e.0 == k)
                .map_or("—".into(), |e| ms(e.1));
            let bytes = self.work["bodies"][k]["body_bytes"]
                .as_u64()
                .map_or("?".into(), |b| b.to_string());
            writeln!(
                w,
                "| {k} | {bytes} | {} [{}, {}] | {l5} |",
                ms(m),
                ms(ci.0),
                ms(ci.1)
            )
            .unwrap();
        }
        if let (Some(((ck, c), (lk, l))), Some((link, chain))) = (self.worst(), self.ceiling()) {
            writeln!(
                w,
                "\n**The measured ceiling** at N = 16: per link, the costliest `Contains` call ({ck}) and line 2 on the costliest body ({lk}); per chain, {LINKS} links and {SCOPE_BODIES} bodies. Line 2 runs before any signature; `Contains` needs a compromised agent's signature. Both are the worst inputs found, so both are lower bounds on the true ceiling.\n\n| | Per link or body (ms) | Per chain (ms) | Per link or body ÷ one strict Ed25519 verification |\n|---|---|---|---|\n| `Contains` at the budget | {} | {} | {} |\n| Line 2 | {} | {} | {} |\n| **Both** | **{}** | **{}** | **{}** |",
                ms(c),
                ms(LINKS as f64 * c),
                x(c),
                ms(l),
                ms(SCOPE_BODIES as f64 * l),
                x(l),
                ms(link),
                ms(chain),
                x(link)
            )
            .unwrap();
            if let Some((k, m, _)) = line5.first() {
                writeln!(
                    w,
                    "\nLine 5's re-encoding, also before any signature, is not in the sum: at most {} ms per body ({k}).",
                    ms(*m)
                )
                .unwrap();
            }
        }
        w.push_str("\n**The frozen generator's shapes the default admits:** the most rules for which the pin-time check on the policy, the link to a child scope one tighter, and the child's own reflexive check all stay within the budget (counts, not timings):\n\n| Atoms per rule | Most rules admitted | W at that size (pin, link, child) | W with one rule more | Largest that fits a body |\n|---|---|---|---|---|\n");
        if let Some(rows) = self.work["admitted_frozen_shapes"].as_array() {
            for r in rows {
                let triple = |v: &Value| {
                    v.as_array().map_or("—".into(), |a| {
                        a.iter()
                            .map(|x| x.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                };
                writeln!(
                    w,
                    "| {} | {}{} | {} | {} | {} |",
                    r["atoms"],
                    r["max_admitted_rules"],
                    if r["contiguous"] == Value::Bool(true) {
                        ""
                    } else {
                        " (not contiguous)"
                    },
                    triple(&r["work_at_max"]),
                    triple(&r["work_one_more"]),
                    r["largest_fitting_rules"]
                )
                .unwrap();
            }
        }
        let o = &self.oracle;
        let wb = &o["work_budget"];
        let pct = |v: &Value| v.as_f64().map_or("?".into(), |c| format!("{c:.4}"));
        writeln!(
            w,
            "\n**Legitimate inputs.** The workload profiles' largest `Contains` count is {}. The differential oracle ({} pairs, seed {}): completeness {} without a budget and {} at the default; {} well-formed pairs and {} reflexivity checks pass the budget; the largest counts are {} (pairs) and {} (reflexivity); soundness violations: {}.",
            self.work["profiles_max_work"],
            o["contains"]["cases"],
            o["seed"],
            pct(&o["contains"]["completeness_overall"]["completeness"]),
            pct(&wb["completeness_overall_at_default_budget"]["completeness"]),
            wb["exhausted_at_default_budget"]["wellformed_pairs"],
            wb["exhausted_at_default_budget"]["reflexivity_checks"],
            wb["max_work_wellformed_pairs"],
            wb["max_work_reflexivity"],
            o["contains"]["soundness_violations"]
        )
        .unwrap();
        w.push_str("\n**The headline cells** with the budget, against the measured build:\n\n");
        match &self.headline {
            Some(h) => w.push_str(&h.markdown(m9)),
            None => w.push_str("_Not run yet: there is no verified archive under `results/exploratory/budget/headline/`._\n"),
        }
        w
    }
}
