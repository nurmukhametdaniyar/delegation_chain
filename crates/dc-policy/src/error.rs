use thiserror::Error;

/// Why a scope was refused. `Malformed` is the paper's term (§6.1): a policy
/// that is malformed is unavailable at line 31 (D-12), and a malformed scope
/// in a body fails decoding at line 2 (D-28). `Syntax` covers the text form
/// only (SPEC §9.1).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PolicyError {
    #[error("malformed scope: {0}")]
    Malformed(String),
    #[error("syntax error at byte {pos}: {msg}")]
    Syntax { pos: usize, msg: String },
}

pub(crate) fn malformed<T>(msg: impl Into<String>) -> Result<T, PolicyError> {
    Err(PolicyError::Malformed(msg.into()))
}
