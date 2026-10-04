//! Workspace-level test host.
//!
//! This package has no code of its own. It exists so that the security suite
//! of SPEC §11.2 can live in `tests/` at the repository root (D-46). The
//! suites run against the protocol's default instantiation, Ed25519 per hop;
//! the `aggregate-variant` feature runs them against the BLS aggregate variant
//! (paper §4.8; D-84).
