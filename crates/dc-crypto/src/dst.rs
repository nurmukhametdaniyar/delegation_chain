/// What a signature is for. BLS signs under a distinct domain-separation tag
/// per purpose (D-04). Ed25519 has no DSTs; there, the digest tags of D-07
/// separate the purposes (SPEC §5.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dst {
    /// Chain signatures σ_0 … σ_N.
    Chain,
    /// Proof of possession at registration.
    Pop,
    /// Approval receipts.
    Receipt,
    /// Registry certificates.
    Cert,
    /// Revocation assertions.
    Revoke,
}

impl Dst {
    pub const ALL: [Dst; 5] = [Dst::Chain, Dst::Pop, Dst::Receipt, Dst::Cert, Dst::Revoke];

    /// The BLS ciphersuite string (D-04). The chain one is the paper's
    /// basic-scheme suite (§4.2).
    pub const fn bls(self) -> &'static [u8] {
        match self {
            Dst::Chain => b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
            Dst::Pop => b"DC-V1-POP_BLS12381G2_XMD:SHA-256_SSWU_RO_",
            Dst::Receipt => b"DC-V1-RCPT_BLS12381G2_XMD:SHA-256_SSWU_RO_",
            Dst::Cert => b"DC-V1-CERT_BLS12381G2_XMD:SHA-256_SSWU_RO_",
            Dst::Revoke => b"DC-V1-REVOKE_BLS12381G2_XMD:SHA-256_SSWU_RO_",
        }
    }
}
