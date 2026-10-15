//! Errors shared by every openfirma crate.

use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("asn.1 encoding failed: {0}")]
    Der(#[from] der::Error),

    #[error("public key info error: {0}")]
    Spki(#[from] spki::Error),

    #[error("unsupported digest algorithm, oid {0}")]
    UnsupportedDigest(String),

    #[error("unsupported key algorithm, oid {0}")]
    UnsupportedKeyAlgorithm(String),

    #[error("{key} keys cannot be combined with the {digest} digest")]
    UnsupportedCombination {
        key: &'static str,
        digest: &'static str,
    },

    #[error("prehash for {alg} must be {expected} bytes, got {got}")]
    PrehashLength {
        alg: &'static str,
        expected: usize,
        got: usize,
    },

    #[error("the signing operation failed: {0}")]
    Signing(String),

    #[error("invalid pkcs#8 private key: {0}")]
    PrivateKey(String),

    #[error("invalid x.509 certificate: {0}")]
    Certificate(String),

    #[error("verification: {0}")]
    Verification(String),

    #[error("pdf: {0}")]
    Pdf(String),

    #[error("keystore: {0}")]
    Keystore(String),

    #[error("the signer carries no certificate")]
    NoCertificate,

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn other(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }
}
