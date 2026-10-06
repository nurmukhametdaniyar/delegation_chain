//! The text the paper reads carries no internal identifiers (D-88): no
//! decision, paper-issue or question numbers (D-79, P-28, Q-02), no
//! pre-registered question numbers (Q5), no milestones (M9) and no dates
//! (2026-09-29). BENCHMARKS.md keeps them; `paper/` must not, comments
//! included, since a LaTeX source is published with its comments. The arm
//! letters are allowed: the paper defines them (§8.3).
//!
//! Every text file under `paper/` is scanned in full. The figures (PDF and
//! PNG) are binary, with their text in compressed streams or pixels, and
//! cannot be read here; their text is drawn by `scripts/paper_figures.py`.
//! Any other binary file fails the test.

use std::fs;
use std::path::{Path, PathBuf};

/// Every internal identifier in `s`.
fn identifiers(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let word = |i: usize| {
        b.get(i)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
    };
    let digits = |i: usize| b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
    let mut found = vec![];
    for i in 0..b.len() {
        if i > 0 && word(i - 1) {
            continue;
        }
        let end = match b[i] {
            // D-79, P-28, Q-02.
            b'D' | b'P' | b'Q' if b.get(i + 1) == Some(&b'-') && digits(i + 2) > 0 => {
                i + 2 + digits(i + 2)
            }
            // Q5, M9; not the chip in "Apple M4 Max".
            b'Q' | b'M' if digits(i + 1) > 0 => {
                let end = i + 1 + digits(i + 1);
                let chip = [" Max", " Pro", " Ultra"]
                    .iter()
                    .any(|x| b[end..].starts_with(x.as_bytes()));
                if b[i] == b'M' && chip {
                    continue;
                }
                end
            }
            // 2026-09-29.
            c if c.is_ascii_digit()
                && digits(i) == 4
                && b.get(i + 4) == Some(&b'-')
                && digits(i + 5) == 2
                && b.get(i + 7) == Some(&b'-')
                && digits(i + 8) == 2 =>
            {
                i + 10
            }
            _ => continue,
        };
        if !word(end) {
            found.push(s[i..end].to_owned());
        }
    }
    found
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let p = e.unwrap().path();
        if p.is_dir() {
            files(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn the_matcher_finds_identifiers_and_nothing_else() {
    assert_eq!(
        identifiers("(D-79) M9's medians, (Q5), P-28, Q-02; revision 2026-09-29. \\S{}Q4 M10"),
        [
            "D-79",
            "M9",
            "Q5",
            "P-28",
            "Q-02",
            "2026-09-29",
            "Q4",
            "M10"
        ]
    );
    let clean = "Arms A, A-ind, B, C, C-batch, D and E; T3b, L23, Theorem 5, \\S{}9.2, \
                 N = 3, BLS12-381, Ed25519, ad2faa6, an Apple M4 Max, AD-1, QM9, M9x, 26-09-29";
    assert_eq!(identifiers(clean), Vec::<String>::new());
}

#[test]
fn paper_artifacts_carry_no_internal_identifiers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../paper");
    let mut all = vec![];
    files(&root, &mut all);
    all.sort();
    let mut text = 0;
    let mut hits = vec![];
    for p in &all {
        let bytes = fs::read(p).unwrap();
        let name = p.strip_prefix(&root).unwrap().display().to_string();
        match String::from_utf8(bytes) {
            Ok(s) => {
                text += 1;
                for (n, line) in s.lines().enumerate() {
                    let ids = identifiers(line);
                    if !ids.is_empty() {
                        hits.push(format!("paper/{name}:{}: {}", n + 1, ids.join(", ")));
                    }
                }
            }
            Err(_) => assert!(
                matches!(p.extension().and_then(|x| x.to_str()), Some("pdf" | "png")),
                "paper/{name} is binary and not a figure, so it cannot be checked"
            ),
        }
    }
    // The eight files in tables/ and the figures' captions.
    assert!(text >= 9, "only {text} text files under paper/");
    assert!(
        hits.is_empty(),
        "internal identifiers under paper/:\n{}",
        hits.join("\n")
    );
}
