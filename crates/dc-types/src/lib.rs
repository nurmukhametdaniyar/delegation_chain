//! Identifiers, bodies, certificates, receipts, wire format and digests
//! (SPEC §5.4, §6, §7).
//!
//! Decoding follows D-31: malformed input is an error ([`Malformed`], line 2);
//! a canonical-form violation in a body is recorded in [`DecodedBody`] and
//! rejected by the verifier at line 5. Scopes are carried as raw CBOR
//! ([`RawScope`]); `dc-policy` validates them (D-28).

mod body;
mod cert;
pub mod digest;
mod envelope;
mod error;
mod ident;
mod params;
mod receipt;
mod time;
mod util;

pub use body::{
    Body, BodyKind, DecodedBody, DelegationBody, InvocationBody, RawScope, SessionBody, decode_body,
};
pub use cert::{
    CERT_VERSION, CertBody, Certificate, ParsedCert, ParsedRevocation, PopChallenge,
    RevocationAssertion, RevocationBody,
};
pub use envelope::{ENVELOPE_LIMITS, Envelope, MAX_CHAIN_BODIES};
pub use error::{BuildError, Malformed};
pub use ident::{IdentError, Identifier, Kind, Principal, is_identifier};
pub use params::Params;
pub use receipt::{ApprovalBody, MAX_ATTESTATION, Receipt};
pub use time::{Clock, ManualClock, SystemClock};
