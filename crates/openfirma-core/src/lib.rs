//! Core types shared by every openfirma crate: digest and signature
//! algorithms, the OID table, certificate handles and the [`Signer`] trait
//! that isolates all key material and all platform crypto.

pub mod alg;
pub mod cert;
pub mod dump;
pub mod error;
pub mod oid;
pub mod signer;
pub mod tlv;
pub mod workflow;

pub use alg::{DigestAlg, KeyAlgorithm, SignatureAlg};
pub use cert::CertificateHandle;
pub use dump::der_dump;
pub use error::{Error, Result};
pub use signer::{Signer, SoftwareSigner, verify_prehash};
